# R1 — Which bytes of a secret file are the secret

**Question.** What do comparable tools do with line endings in a password/passphrase file, and
does the PRD's **FR-8** rule (strip exactly one trailing `\n` or `\r\n`, nothing else; exit 2 on
a multi-line file) match or diverge from them? Decides **OD-2**, **OD-3** and **OD-7**.

All source citations below were fetched 2026-07-25 and are pinned to the commit named in §6.

---

## 1. Primary sources

### 1.1 go-ethereum — the parity target for S-C (v3 / `account`)

Two hops matter. Hop one is file → string; hop two is string → scrypt input. **Both** are needed
before any claim of v3 parity can be made.

**Hop one — `readPasswordFromFile`, `cmd/geth/accountcmd.go:226-240` (master):**

```go
// readPasswordFromFile reads the first line of the given file, trims line endings,
// and returns the password and whether the reading was successful.
func readPasswordFromFile(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	text, err := os.ReadFile(path)
	if err != nil {
		utils.Fatalf("Failed to read password file: %v", err)
	}
	lines := strings.Split(string(text), "\n")
	if len(lines) == 0 {
		return "", false
	}
	// Sanitise DOS line endings.
	return strings.TrimRight(lines[0], "\r"), true
}
```

Called at `accountcmd.go:259` (`account new`), `:329` (`account update`), `:357` (`account import`),
i.e. every non-interactive `geth account` path. The flag is `PasswordFileFlag`,
`cmd/utils/flags.go:618-623`, `Usage: "Password file to use for non-interactive password input"`.

The rule is therefore, exactly: **read the whole file · split on `\n` · take element 0 · strip
*all* trailing `\r` from it.** It is **first-line-wins**, and the CR strip is a `TrimRight`
(unbounded repetition), not a single-terminator strip.

The same three lines appear inline a second time in the dev-mode path,
`cmd/utils/flags.go:2012-2019` — independent confirmation that this is geth's settled semantics
and not an accident of one call site.

Historically the shared helper was **`utils.MakePasswordList`**, `cmd/utils/flags.go:1287-1302`
at tag `v1.13.15`:

```go
	lines := strings.Split(string(text), "\n")
	// Sanitise DOS line endings.
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines
```

— identical per-line treatment, but it returns **every** line, because geth's `--password` is by
design a password *list*: `utils.GetPassPhraseWithList(text, confirmation, index, passwords)`
(`cmd/utils/prompt.go:51-62`, v1.13.15) selects `passwords[index]` for the *i*-th account being
unlocked and reuses the last entry once the list runs out. **This is why geth accepts multi-line
files — it is a feature of a different feature (`--unlock` of N accounts), not a lenience about
stray bytes.** It is the single most important context for OD-3 (§4).

**Hop two — the string reaches scrypt raw**, `accounts/keystore/passphrase.go` (master):

```
:184  func EncryptKey(key *Key, auth string, scryptN, scryptP int) ([]byte, error) {
:186      cryptoStruct, err := EncryptDataV3(keyBytes, []byte(auth), scryptN, scryptP)
:145      derivedKey, err := scrypt.Key(auth, salt, scryptN, scryptR, scryptP, scryptDKLen)
:334      authArray := []byte(auth)          // DecryptDataV3
:345      return scrypt.Key(authArray, salt, n, r, p, dkLen)
```

No NFKD, no control-character strip, no trim — `[]byte(auth)` straight into `scrypt.Key`. This
**confirms the comment at `encrypt_v3.rs:150`** ("RAW passphrase — never normalize (C-4).
geth/MetaMask use raw UTF-8") from the source, and it is what makes S-C sensitive to every byte
the file-reading layer hands it.

### 1.2 OpenSSL — `-pass file:` (well-specified prior art)

`app_get_pass`, `apps/lib/apps.c:219-307` (master). The `file:` branch opens a file BIO
(`:237-242`), then, common to all sources:

```c
    i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
    ...
    tmp = strchr(tpass, '\n');
    if (tmp != NULL)
        *tmp = 0;
    return OPENSSL_strdup(tpass);
```

- **One line only** — `BIO_gets` stops at the first `\n`. Confirms the charter's expectation.
- **Bounded read**: `char tpass[APP_PASS_LEN]` with `#define APP_PASS_LEN 1024`
  (`apps/include/apps.h:360`). A password longer than 1023 bytes is silently truncated, not an
  error. This is the only hard number any of these tools puts on a secret-file read — see
  [`r2`](r2-file-reading-policy.md) §1.
- **`\r` is NOT stripped.** The truncation is at `\n`; a preceding `\r` survives into the
  password.
- `file:` shares the code path with `env:`, `fd:` and `stdin` (`:228-280`), so OpenSSL treats
  "environment variable" and "file" as peers of one `pass:`-style source syntax rather than
  ranking one as secure.

### 1.3 GnuPG — `--passphrase-file`

Documented: *"Read the passphrase from file file. **Only the first line will be read from file
file.**"* (and the identical sentence for `--passphrase-fd`) —
<https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html>.

Source, `g10/passphrase.c:114-152` (`read_passphrase_from_fd`, master): a byte-at-a-time loop
that breaks on `read(...) != 1 || pw[i] == '\n'`, then NUL-terminates. **First line, `\r` not
stripped** — same shape as OpenSSL, not geth. (Its growth loop uses `xmalloc_secure` /
`xfree` — relevant to FR-23, see [`r2`](r2-file-reading-policy.md) §3.)

### 1.4 clef — no password-file option exists

`cmd/clef/` is **absent from go-ethereum master** (raw fetch → HTTP 404); at `v1.13.15` the only
password inputs are `utils.GetPassPhrase` (interactive `/dev/tty` prompt — `cmd/clef/main.go:339`,
`:429`, `:848`) and the JSON `stdio-ui` channel's `OnInputRequired` (`main.go:838-846` inside
`readMasterKey`). `--signersecret` names the *encrypted master-seed file*, not a password file.

**clef therefore contributes no line-ending convention.** Its deliberate refusal to offer a
non-interactive password file is itself the datum.

### 1.5 staking-deposit-cli / ethstaker-deposit-cli — no password-file option either

- Passwords arrive as **argv strings**: `param_decls='--keystore_password'`
  (`staking_deposit/cli/generate_keys.py:82-92`), `--mnemonic_password`
  (`staking_deposit/cli/existing_mnemonic.py:40-51`), both `click` options with
  `hide_input=True` and an interactive fallback prompt. The maintained fork is identical
  (`ethstaker_deposit/cli/generate_keys.py:88-99`).
- Normalization, `staking_deposit/key_handling/keystore.py:119-126`:

```python
    def _process_password(password: str) -> bytes:
        """
        Encode password as NFKD UTF-8 as per:
        https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md#password-requirements
        """
        password = normalize('NFKD', password)
        password = ''.join(c for c in password if ord(c) not in UNICODE_CONTROL_CHARS)
        return password.encode('UTF-8')
```

This is byte-for-byte the contract `normalize_passphrase` implements (`crypto.rs:35-46`).

**Conclusion for S-B: there is no file convention to match.** The reference implementation has no
password-file input at all — its only non-interactive path is the argv exposure this whole change
exists to remove. S-B is unconstrained by parity *and* insensitive by construction (§3.2).

### 1.6 Secret-manager conventions (background for §3, detail in `r2`)

| Source | Path | Mode | Trailing newline |
|---|---|---|---|
| Docker Swarm | `/run/secrets/<name>` | `-r--r--r--` (0444), per <https://docs.docker.com/engine/swarm/secrets/> | none added — the stored bytes verbatim |
| Kubernetes | projected volume, file is a **symlink** to `..data/<key>` (`pkg/volume/util/atomic_writer.go:50-133`) | `SecretVolumeSourceDefaultMode int32 = 0644` (`staging/src/k8s.io/api/core/v1/types.go:1572-1574`) | none added |
| `pass` (password-store) | no file — `pass show name` writes to stdout | n/a | prints a trailing newline |

*Reasoning, not citation:* because Docker and Kubernetes write the stored bytes with no
terminator, a secret mounted from either is the **no-trailing-newline** case, while a secret
produced by `echo`, `pass show > f`, or most editors is the **one-trailing-`\n`** case. Any rule
that does not accept both identically is broken for one of the two populations.

## 2. The cross-tool decode table

What each tool yields as the secret, for the same file bytes. `⟨FR-8⟩` is the PRD rule exactly as
written today; `⟨rec⟩` is §5's recommendation. Verified by re-implementing geth's two lines and
FR-8 side by side and diffing every row.

| File bytes | geth | OpenSSL `file:` | gpg | ⟨FR-8⟩ | ⟨rec⟩ |
|---|---|---|---|---|---|
| `pw` | `pw` | `pw` | `pw` | `pw` | `pw` |
| `pw\n` | `pw` | `pw` | `pw` | `pw` | `pw` |
| `pw \n` (trailing space) | `pw ` | `pw ` | `pw ` | `pw ` | `pw ` |
| `pw\r\n` | `pw` | **`pw\r`** | **`pw\r`** | `pw` | **exit 2** |
| **`pw\r`** | `pw` | `pw\r` | `pw\r` | **`pw\r`** | **exit 2** |
| **`pw\r\r\n`** | `pw` | `pw\r\r` | `pw\r\r` | **`pw\r`** | **exit 2** |
| `pw\nmore\n` | `pw` | `pw` | `pw` | exit 2 (FR-9) | exit 2 |
| `` (0 bytes) | `""` | error, `"Error reading password from BIO"` | `""` | `""` | `""` (FR-18) |
| `\n` | `""` | `""` | `""` | `""` | `""` (FR-18) |

Four results fall out of this table.

1. **The plain cases all agree.** `pw`, `pw\n` → every tool yields `pw`, and so does FR-8. This is
   the overwhelming majority of real files and it is already correct.
2. **Every tool keeps a trailing space.** No survey member trims horizontal whitespace, so FR-8's
   "a trailing space or tab is part of the secret" (FR-11) is not a house rule — it is the
   universal one. This matters for §5: the discriminator between "strip" and "keep" is not
   whether a byte is visible, it is whether the tools agree the byte is a line terminator.
3. **FR-8 as written diverges from geth in exactly two rows, and FR-9 catches neither.** `pw\r`
   and `pw\r\r\n` contain no residual `\n` after FR-8's strip, so the file is accepted and the
   secret silently retains one or more `\r` that geth would have removed. **This is the finding.**
   §3.1 states what it costs.
4. **`\r\n` is the one row where the tools genuinely disagree with each other**: geth strips the
   `\r`, OpenSSL and gpg keep it. There is no "what everyone does" to inherit, so any rule that
   *accepts* a CRLF file is picking a side and hard-coding it into a derived key. §5 refuses
   instead.

## 3. Which repo path each finding governs

The three consumers have genuinely different exposure; a single blanket answer would be useless.

### 3.1 S-C — v3 keystore, `account new` / `account recover` (RAW bytes) — **the divergence lives here**

`encrypt_v3.rs:150` passes `input.password` to `crypto::derive_scrypt` untouched;
`decrypt_v3.rs:116` does the same. Every byte changes the derived key.

Concretely, for a file containing `hunter2hunter2\r` (no `\n` — a lone CR, e.g. a file that was
line-ending-mangled in transit, or authored on a system emitting bare CRs):

- **ethernal under FR-8-as-written** encrypts under the 15 bytes `hunter2hunter2\r`.
- **geth reading the same file** derives from the 14 bytes `hunter2hunter2`.

The keystore ethernal writes cannot be opened by `geth account import --password <same file>`,
and a v3 keystore created by geth from that file cannot be opened by
`ethernal account recover --passphrase-file <same file>`. **That divergence — one file, two v3
keys — is the reason to act.** Same reasoning for `pw\r\r\n`: FR-8 strips the `\r\n` and keeps one
`\r`; geth's `TrimRight` removes both.

Invisibility is not the argument for rejecting — a trailing space is equally invisible and is
deliberately kept (FR-11, and §2 finding 2: every tool keeps it). Invisibility is the reason the
divergence goes **undetected**: both failures surface as "wrong passphrase" against a file the
operator can see is correct in `cat`, because a bare `\r` repositions the cursor rather than
printing. Measured — `cat` output for `hunter2hunter2\r` and `hunter2hunter2` is
character-for-character the same on this terminal; only `xxd` distinguishes them. So the operator
who hits this has no local means of diagnosing it.

**This is the answer OD-7 asked for: FR-8's rule does *not* hold for the v3/geth parity case in
the CR sub-cases.** §5 gives the one-clause amendment that restores it.

### 3.2 S-B — v4 / EIP-2335, `validator` + `deposit gen` (normalized) — insensitive, and unconstrained

`normalize_passphrase` (`crypto.rs:35-46`) NFKDs then drops every code point matched by
`is_stripped_control` — `u <= 0x1f` covers both `\n` (0x0A) and `\r` (0x0D) (`crypto.rs:52`).
Both are removed **wherever they occur**, not only at the end. So for S-B:

- FR-8's strip is a no-op — as the PRD already records at FR-12 ("S-B passes whether or not FR-8
  is implemented"). All four table rows above collapse to `pw`.
- `staking-deposit-cli` does the identical thing (§1.5), so cross-tool parity for the validator
  path holds for **any** of the candidate rules.
- The one thing *not* stripped is a trailing **U+0020 space** — already correctly flagged in PRD
  §4.2 and FR-11.

S-B imposes no constraint on OD-2. It is a regression guard on the normalizer, nothing more.

### 3.3 S-D — BIP-39 mnemonic passphrase — **no prior art exists; say so**

`to_seed` (`bip39.rs:181-201`) hard-fails non-UTF-8, then builds `"mnemonic" ‖ passphrase`, NFKDs
the whole salt, and PBKDF2s it. **No control strip, no trim** — deliberately, per the function's
own doc comment ("a mis-encoded '25th word' cannot silently derive an unrecoverable seed").

BIP-39 defines the passphrase as an exact string and defines no file encoding for it. No tool in
the survey — geth, clef, OpenSSL, gpg, staking-deposit-cli, ethstaker fork — offers a
mnemonic-passphrase *file*. **The absence is genuine, not a gap in this search.** Recommending a
rule for S-D therefore cannot be an appeal to parity; it rests on two things that *are*
established here:

1. The failure is **silent and total**. A stray `\n` or `\r` changes the seed, which changes
   every derived pubkey at every index. C1–C4 all pass — they verify the keystore round-trips,
   not that the seed was the intended one (`r3-verification-semantics.md` §2). The operator
   discovers it after 32 ETH is on-chain against a validator they cannot sign for.
2. Predictability beats cleverness. Under "strip one terminator + reject anything with a residual
   CR/LF", the operator can always predict the secret bytes from what `cat` shows, because every
   byte sequence where `cat` would lie is refused.

Applying the same rule to S-D as to S-B/S-C also keeps **FR-10** intact, which matters more here
than anywhere: an operator must not have to know that the 25th-word file obeys different rules
from the keystore-passphrase file *sitting next to it in the same ceremony*.

### 3.4 An asymmetry FR-10 does not cover: non-UTF-8 bytes

*Observation for architecture, not a new requirement.* An env var could not carry non-UTF-8
bytes — `std::env::var` returns `Err`, which `EnvSource` folds into `EnvVarEmpty`
(`passphrase.rs:54-64`). A **file can**. The same invalid byte then behaves three different ways:

| Consumer | Behavior on a non-UTF-8 byte |
|---|---|
| S-B (v4) | `String::from_utf8_lossy` → U+FFFD → **silently different derived key** (`crypto.rs:38-44`, explicit in the comment: "which would change the derived key") |
| S-C (v3) | raw byte, meaningful, round-trips correctly |
| S-D (mnemonic) | hard error `Bip39Error::PassphraseNotUtf8` (`bip39.rs:187`) |

Today this is unreachable from the CLI. After this change it is reachable from all three flags.
It is pre-existing behavior and out of scope to fix, but architecture should decide consciously
whether `FileSource` validates UTF-8 at the boundary (making all three fail closed, matching S-D)
or preserves each consumer's current behavior. The silent one is S-B.

## 4. Testing the PRD's own subset argument (OD-3)

The PRD argues (FR-9, OD-3) that exit-2-on-multi-line is a **strict subset** of first-line-wins,
so refusing now preserves the option to relax later without invalidating any key already created.
Tested against geth's actual body:

- **It holds** for every file with no CR: geth's `strings.Split(text, "\n")[0]` on a file that is
  `secret` or `secret\n` yields exactly the bytes FR-8 yields — and so do OpenSSL and gpg.
  Relaxing FR-9 to first-line-wins later would decode every previously-accepted file identically. ✅
- **It fails** for exactly the CR rows of §2 — where FR-8 accepts a file and yields *different*
  bytes from geth's first-line-wins (`pw\r`, `pw\r\r\n`), or where the three tools disagree among
  themselves (`pw\r\n`). ❌
- With the §5 amendment the failing rows become exit 2, the accepted set contains no CR at all,
  and the property holds against **all three** tools without exception.

So the subset argument is **a strong reason to keep FR-9, conditional on closing the CR gap** —
which is the same amendment OD-7 needs. One change fixes both.

Two clarifications the PRD should absorb:

- **FR-9 is a deliberate divergence from geth, not parity.** geth accepts multi-line files because
  `--password` is a password *list* indexed per unlocked account (§1.1), a feature ethernal does
  not have and does not want. State it that way in the user guide; do not imply geth would reject
  a multi-line file.
- **Empty files agree with geth by accident, not design.** `strings.Split("", "\n")` → `[""]`, so
  geth's `account new --password /dev/null` creates a key under an empty password. FR-18's split
  ruling (empty is valid for the mnemonic passphrase, exit 2 for a keystore passphrase) is
  *stricter* than geth for the keystore case and matches OpenSSL's behavior (`BIO_gets` returns
  ≤ 0 → error). FR-18 needs no change; it is simply not a parity claim.

## 5. Recommendation

**The principle the evidence supports: strip only what every surveyed tool agrees is a line
terminator, keep what every surveyed tool agrees is content, and refuse what they disagree about.**
That principle is what makes FR-8 and FR-11 consistent with each other — a trailing space is kept
not because it is visible but because geth, OpenSSL and gpg all keep it (§2, finding 2); a
trailing `\n` is stripped because all three strip it. Applied to `\r`, it yields:

> **FR-8 (amended).** Strip **exactly one** trailing `\n`. Nothing else: interior bytes, leading
> whitespace, and a trailing space or tab are part of the secret.
>
> **FR-9 (amended).** If **any `\n` or `\r` remains anywhere** in the result, that is a
> configuration error: **exit 2**, message names the path and what was found (a line count, or
> "carriage return"), never the content.

Two clauses: the `\r\n` alternative leaves FR-8, and FR-9's residual check widens from `\n` to
`\n`-or-`\r`. A CRLF file is then rejected by FR-9, not accepted by FR-8.

| Property | Status |
|---|---|
| Byte-identical to **geth, OpenSSL and gpg alike** for every file the rule accepts | ✅ (FR-8 as written matched only geth, and not on `pw\r` / `pw\r\r\n`) |
| Strict-subset-of-first-line-wins, so FR-9 stays reversible | ✅ without exception, against all three tools (§4) |
| Consistent with FR-11's keep-the-trailing-space rule | ✅ — same principle, opposite answer |
| One rule for all three flags and all commands (FR-10) | ✅ unchanged |
| `printf '%s' pw > f` and `echo pw > f` identical | ✅ unchanged |
| The repo's `$(cat …)` verify-skill workflow stays byte-identical | ✅ unchanged (PRD §4.2 note) |
| Any file containing a `\r` | **exit 2** — loud, where FR-8-as-written was silently wrong on two of the three CR shapes |
| Statement in one sentence for the user guide | "The secret is the whole file minus at most one trailing newline; a carriage return anywhere is an error." |

Rejected alternatives, briefly, so they are not re-derived downstream:

- **Keep FR-8's `\r\n` clause (accept CRLF, strip it).** Matches geth, but hard-codes into a
  derived key the one resolution the three tools disagree about (§2, finding 4) — OpenSSL and gpg
  would read `pw\r` from the same file. It is also the one choice here that is **not reversible**:
  refusing CRLF now can be relaxed to stripping it later without invalidating any key, and the
  converse is false. *If the gate wants Windows-authored files to work without `dos2unix`, this is
  the single fallback — it is strictly worse only in those two respects, and it still requires
  FR-9's widening to catch bare and doubled CRs.*
- **`TrimRight` all trailing `\r` (geth-exact).** Also reaches geth parity, but extends the
  disagreement to every CR shape and locks in geth's reading against OpenSSL's and gpg's.
- **No trim at all.** Makes `echo pw > f` derive an unintended key — silently, for S-D. Diverges
  from every tool surveyed and from the repo's own workflow.
- **First-line-wins (geth-shaped).** Makes the derived key depend on content past the first line;
  the subset argument (§4) says it can be adopted later without invalidating anything, so there is
  no cost to deferring it and a real cost to adopting it now.

**Consequences for the two open manual parity gates.** H9 (validator) and A5-M (EOA) must each
gain a bare-CR case and a CRLF case, both asserting **exit 2**, and the EOA gate must round-trip
against real `geth account` on the plain cases — `geth account import --password <file>` on a
keystore ethernal wrote from the same file, and `ethernal account recover --passphrase-file
<file>` on one geth wrote, for a file with and without a trailing `\n`. The CR rows of §2 are the
only place the two implementations can disagree, so they are the only rows the gate must exercise
beyond the plain case. The automated equivalent is FR-12 — see [`index.md`](index.md), finding 2.

## 6. Sources

Pinned commits, fetched 2026-07-25.

| Source | Reference |
|---|---|
| go-ethereum (master, `ca1f2e4d38f4e94676981bb9251239a5d490b004`) | [`cmd/geth/accountcmd.go`](https://github.com/ethereum/go-ethereum/blob/ca1f2e4d38f4e94676981bb9251239a5d490b004/cmd/geth/accountcmd.go#L226-L240) · [`cmd/utils/flags.go`](https://github.com/ethereum/go-ethereum/blob/ca1f2e4d38f4e94676981bb9251239a5d490b004/cmd/utils/flags.go#L618-L623) · [`accounts/keystore/passphrase.go`](https://github.com/ethereum/go-ethereum/blob/ca1f2e4d38f4e94676981bb9251239a5d490b004/accounts/keystore/passphrase.go#L140-L186) |
| go-ethereum `v1.13.15` | [`cmd/utils/flags.go#L1287-L1302`](https://github.com/ethereum/go-ethereum/blob/v1.13.15/cmd/utils/flags.go#L1287-L1302) · [`cmd/utils/prompt.go#L51-L62`](https://github.com/ethereum/go-ethereum/blob/v1.13.15/cmd/utils/prompt.go#L51-L62) · [`cmd/clef/main.go#L819-L850`](https://github.com/ethereum/go-ethereum/blob/v1.13.15/cmd/clef/main.go#L819-L850) |
| OpenSSL (master, `971b8d060e52499d6ffd2f9ca697fe23f72a629a`) | [`apps/lib/apps.c#L219-L307`](https://github.com/openssl/openssl/blob/971b8d060e52499d6ffd2f9ca697fe23f72a629a/apps/lib/apps.c#L219-L307) · [`apps/include/apps.h#L360`](https://github.com/openssl/openssl/blob/971b8d060e52499d6ffd2f9ca697fe23f72a629a/apps/include/apps.h#L360) |
| GnuPG (master, `3a8c7edec6c8da093e08bc6cbf63e36507da7149`) | [`g10/passphrase.c#L114-L152`](https://github.com/gpg/gnupg/blob/3a8c7edec6c8da093e08bc6cbf63e36507da7149/g10/passphrase.c#L114-L152) · [option docs](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html) |
| staking-deposit-cli (master, `5d4715f73585a491656a57133034adfaece71891`) | [`key_handling/keystore.py#L119-L126`](https://github.com/ethereum/staking-deposit-cli/blob/5d4715f73585a491656a57133034adfaece71891/staking_deposit/key_handling/keystore.py#L119-L126) · [`cli/generate_keys.py#L82-L92`](https://github.com/ethereum/staking-deposit-cli/blob/5d4715f73585a491656a57133034adfaece71891/staking_deposit/cli/generate_keys.py#L82-L92) · [`cli/existing_mnemonic.py#L40-L51`](https://github.com/ethereum/staking-deposit-cli/blob/5d4715f73585a491656a57133034adfaece71891/staking_deposit/cli/existing_mnemonic.py#L40-L51) |
| ethstaker-deposit-cli (main, `ec870d12b4ccce2d53a725ef88d147bb3a79ab98`) | [`cli/generate_keys.py#L88-L99`](https://github.com/ethstaker/ethstaker-deposit-cli/blob/ec870d12b4ccce2d53a725ef88d147bb3a79ab98/ethstaker_deposit/cli/generate_keys.py#L88-L99) |
| Kubernetes (master) | [`api/core/v1/types.go` `SecretVolumeSourceDefaultMode = 0644`](https://github.com/kubernetes/kubernetes/blob/0f317be40dfb054367e4f126845c91ffdd22cdb8/staging/src/k8s.io/api/core/v1/types.go#L1572-L1574) · [`pkg/volume/util/atomic_writer.go#L50-L133`](https://github.com/kubernetes/kubernetes/blob/0f317be40dfb054367e4f126845c91ffdd22cdb8/pkg/volume/util/atomic_writer.go#L50-L133) |
| Docker Swarm secrets | <https://docs.docker.com/engine/swarm/secrets/> |

**Connections:** [`r2-file-reading-policy.md`](r2-file-reading-policy.md) ·
[`index.md`](index.md) · PRD §4.2, OD-2, OD-3, OD-7
