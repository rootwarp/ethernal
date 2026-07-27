# PRD — replace env-var-name flags with file-path flags

**Status:** draft · **Date:** 2026-07-25 · **Target branch:** `develop`
**Plan root:** `docs/plan/env-to-file-flags/`

---

## 1. Summary

Three `ethernal` flags take the **name of an environment variable** as their argument. The
tool then reads the secret out of that variable. Replace all three with flags that take a
**path to a file** holding the secret:

| Today | Replacement | Commands |
|---|---|---|
| `--private-key-env VAR` (default `ETHERNAL_TX_PRIVATE_KEY`) | `--private-key-file PATH` | `tx sign` (`sign_cmd.rs:82`), `tx run` (`run_cmd.rs:72`) |
| `--passphrase-env VAR` | `--passphrase-file PATH` | `deposit gen` (`gen_cli.rs:122`), `validator new`/`recover` + `account new`/`recover` (`keystore_cli.rs:74`) |
| `--mnemonic-passphrase-env VAR` | `--mnemonic-passphrase-file PATH` | `validator`/`account` `new`+`recover` (`keystore_cli.rs:94`) |

The flag rename is the small part. The change is worth a plan because reading a secret from a
file forces three decisions that reading it from an environment variable never posed:
**exactly which bytes of the file are the secret** (§4.2 — this determines derived keys and is
the ship-blocking risk), **what file the tool is willing to read** (§4.3), and **what happens
to the one command that today needs no key flag at all** (§4.4). It also inverts a security
invariant the code currently states in its own doc comments (§4.5).

## 2. Problem

### 2.1 Environment variables leak sideways, and this repo has a concrete instance

The generic argument is familiar: an env var is visible in `/proc/PID/environ` to any
same-uid process, survives in shell history via `export VAR=secret` (the user guide already
warns about this — `docs/USER-GUIDE.md:200`), and lands whole in CI log dumps.

The repo-specific instance is stronger. `deposit gen --verify-with-deposit-cli` spawns the
external `staking-deposit-cli` with `std::process::Command::new(cli_path)` and **no
`.env_clear()`** (`gen_cmd.rs:406`). The keystore passphrase the operator supplied via
`--passphrase-env` is therefore inherited, in full, by a third-party Python binary the tool
does not control. A file path in argv is inherited too — but the path is not the secret, and
reading the file requires the child to take a deliberate action rather than merely existing.

### 2.2 The env-name flags carry their own footguns

`--private-key-env` is validated by `is_posix_env_var_name` (`sign_cmd.rs:204`) purely so a
user who types `--private-key-env 0xabc...` — the *value* instead of the *name* — gets an
error instead of a confusing "variable is not set" (`sign_cmd.rs:112`). The file form has the
same failure mode in a different shape and needs its own guard (FR-19).

### 2.3 What a file changes that an env var did not

An env var is a `String`: it has no permissions, no line endings, no "is it a directory",
and it cannot be read twice with different results. A file has all four. §4.2–§4.4 are
requirements that exist *only* because the source became a file.

## 3. Users and success

**Primary user:** a staking operator on an air-gapped or bastion host, feeding a keystore
passphrase and/or a BIP-39 "25th word" into a one-shot ceremony worth 32 ETH per key.
**Secondary:** a CI job running `tx sign --signer local` against a testnet.

**Success metrics**

| # | Metric | Target |
|---|---|---|
| M-1 | Keys derived from a file-supplied secret that differ from the same secret supplied via today's env path | 0, across all four secret consumers in §4.2 (S-C and S-D are the two that can actually regress — see FR-12) |
| M-2 | Flags whose argument is an environment variable name | 0 |
| M-3 | Occurrences of file *contents* in any stdout/stderr/log/`Debug` output | 0, asserted per error path |
| M-4 | New third-party dependencies | 0 |
| M-5 | Public library items removed | 0 (`EnvSource`, `new_local_signer_from_env` retained — §4.5) |
| M-6 | Doc comments still asserting env is the secure source after the change | 0 |

## 4. Requirements

Priority: **P0** ship-blocking · **P1** ship with it unless it forces a redesign · **P2** may
be deferred with a written disposition.

### 4.1 Flag surface

| # | Pri | Requirement |
|---|---|---|
| **FR-1** | P0 | The three `-env` flags are **removed**, not aliased. A leftover `--passphrase-env` in a script must fail as an unknown flag (clap exit 2), never silently do something else. |
| **FR-2** | P0 | Replacements are named `--private-key-file`, `--passphrase-file`, `--mnemonic-passphrase-file`, take `value_name("PATH")`, and appear in the `override_usage` strings (`sign_cmd.rs:40`, `gen_cli.rs:71`, `validator_cli.rs:92`/`:111`, `account_cli.rs:81`/`:100`). |
| **FR-3** | P0 | The mnemonic passphrase keeps its four-form matrix, with `Env` swapped for `File`: `--mnemonic-passphrase VALUE` → raw · bare `--mnemonic-passphrase` → TTY prompt · `--mnemonic-passphrase-file PATH` → file · absent → empty. The `conflicts_with` pairing between the raw/bare flag and the file flag is preserved (`keystore_cli.rs:87`,`:97`). |
| **FR-4** | P0 | `MnemonicPassphraseForm::Env { var, value }` becomes `File { path, value }`. Its hand-written `Debug` (`keystore_cli.rs:45-58`) keeps the **path visible** and the value `[REDACTED]`, exactly as it does for `var` today. Same for `ValidatorConfig`/`AccountConfig`/`GenConfig` field renames (`validator_cli.rs:43`, `account_cli.rs:44`, `gen_cli.rs:33`). |
| **FR-5** | P0 | `--passphrase-file` keeps today's "omit → TTY prompt-with-confirm" behavior. Absent flag is not an error. |
| **FR-6** | P0 | `-` is **not** an accepted path value; it is rejected at load time (exit 2) with a message naming the alternative. Rationale: stdin is already claimed by `tx sign --input -` and by `validator recover`'s piped-mnemonic path (`keygen.rs`, `RecoverMnemonicSource`), and the `require_tty_for_new` guard (`keystore_cli.rs:106`) reasons about stdin being a TTY. Nothing is lost — `/dev/stdin` and `/dev/fd/N` remain reachable as ordinary paths, and process substitution (`--passphrase-file <(gpg -d pw.gpg)`) is the documented no-disk-file pattern. |

### 4.2 Which bytes are the secret — the ship-blocking requirement

Passphrase bytes feed scrypt (keystore) or PBKDF2 (BIP-39 seed) and therefore *determine the
derived key*. `echo pw > f` appends `\n`; `printf '%s' pw > f` does not. Whether that byte is
part of the secret is not a style question. The four consumers do **not** behave the same way,
and this is settled by code, not by preference:

| # | Secret | Consumer | Downstream normalization | Effect of a trailing `\n` |
|---|---|---|---|---|
| **S-A** | hex private key | `new_local_signer_from_hex` (`local.rs:87`) | strip `0x`, require 64 chars, hex-decode | parse failure — **loud** |
| **S-B** | keystore passphrase, `validator`/`deposit gen` (EIP-2335 v4) | `normalize_passphrase` (`crypto.rs:35`): NFKD then strip C0/C1/Delete | **none** — `\n` is 0x0A, and `is_stripped_control` strips `u <= 0x1f` (`crypto.rs:52`). Note a trailing **U+0020 space is not stripped.** |
| **S-C** | keystore passphrase, `account` (v3) | **RAW bytes**, normalization deliberately skipped (`encrypt_v3.rs:150`, `decrypt_v3.rs:116`) | different derived key — surfaces as wrong-passphrase on the next unlock |
| **S-D** | mnemonic passphrase ("25th word") | `to_seed` (`bip39.rs:191`): NFKD of `"mnemonic" ‖ passphrase`, **no control strip, no trim** | **different seed → a different pubkey at every index, silently.** C1–C4 verify the keystore round-trips; nothing verifies the seed was the intended one. |

S-D is the reason this section is P0. It is the only path where a stray byte produces a
fully-valid, fully-verified keystore for the wrong validator, discovered after the deposit is
on-chain.

**S-B is unconstrained by parity, and the plan can stop worrying about it.**
`staking-deposit-cli` has **no** password-file option at all — its only non-interactive path is
`--keystore_password` in argv, the exposure this change exists to remove — and its
`_process_password` (`staking_deposit/key_handling/keystore.py:119-126`) is byte-for-byte the
contract `normalize_passphrase` implements. Every candidate line-ending rule yields the same v4
result, so S-B constrains nothing. ([`r1`](research/r1-secret-file-line-endings.md) §1.5, §3.2)

| # | Pri | Requirement |
|---|---|---|
| **FR-7** | P0 | **Hex private key (S-A):** all leading and trailing ASCII whitespace is trimmed before parsing. Unambiguous — hex contains no whitespace. |
| **FR-8** | P0 | **All three passphrase files (S-B, S-C, S-D):** strip **exactly one trailing `\n`**, and nothing else. No other trimming: interior bytes, leading whitespace, and a trailing space or tab are part of the secret. **Amended after R1** — the original rule also accepted a trailing `\r\n`; see FR-9 and OD-2. |
| **FR-9** | P0 | If **any `\r` or `\n` remains anywhere** in the result, that is a configuration error: **exit 2**, message naming the path and what was found (a line count, or "carriage return"), never the content. This covers both a multi-line file and every carriage-return shape — `pw\r`, `pw\r\n`, `pw\r\r\n`. **Widened after R1**, which found the CR cases decisive: geth strips *all* trailing CRs — `strings.TrimRight(lines[0], "\r") // Sanitise DOS line endings.`, verified in `cmd/utils/flags.go` (`SetEthConfig`) — while OpenSSL's `app_get_pass` truncates at the first `\n` (`tmp = strchr(tpass, '\n'); if (tmp != NULL) *tmp = 0;`, `apps/lib/apps.c`) and **keeps** the `\r`; GnuPG's `read_passphrase_from_fd` agrees with OpenSSL per R1 (not independently verified — see `research/r4-verification-log.md` §4). So on `pw\r` and `pw\r\r\n` the original FR-8 accepted the file and derived a **different v3 key from the same bytes than geth would**, and on `pw\r\n` the three tools disagree with each other, meaning any acceptance hard-codes one reading into a derived key. Refusing is also the reversible direction: refusing CRLF can be relaxed to stripping it later without invalidating a key already created; the converse is false. |
| **FR-10** | P0 | One rule, all three flags, all commands. No per-command or per-keystore-version variation — an operator must never have to know that v4 tolerates what v3 does not. |
| **FR-11** | P0 | The rule is stated **in bytes** in `docs/USER-GUIDE.md`, with the `printf '%s' pw > f` vs `echo pw > f` example and an explicit note that a trailing **space** is significant. One-sentence form: *"The secret is the whole file minus at most one trailing newline; a carriage return anywhere is an error."* The guide must also state that FR-9's multi-line rejection is a **deliberate divergence, not parity** — geth accepts multi-line files because `--password` is a password *list* indexed per unlocked account, a feature ethernal does not have. |
| **FR-12** | P0 | A test per consumer proves the rule is live. For S-B, S-C and S-D: a file with a trailing `\n` and the same file without one produce **identical** output (same decryptable keystore / same derived pubkey set), and the S-D case must additionally match the pubkeys derived via `--mnemonic-passphrase VALUE` with the same value. **Plus, for S-C and S-D, three CR rows: `pw\r`, `pw\r\n` and `pw\r\r\n` each exit 2.** Note that **S-B passes whether or not FR-8/FR-9 are implemented** — `normalize_passphrase` strips both `\n` and `\r` wherever they occur (`crypto.rs:52`, `u <= 0x1f`) — so only **S-C and S-D are live checks**, and those three CR rows are the *only* automated evidence that FR-9's widened clause is live. S-B is retained as a regression guard on the normalizer, not as evidence for FR-8. |
| **FR-12b** | P0 | **Non-UTF-8 bytes must be a conscious decision, not an accident.** `std::env::var` returns `Err` on non-UTF-8, which `EnvSource` folds into `EnvVarEmpty` (`passphrase.rs:54-64`) — an env var could not carry such bytes. **A file can**, and the same invalid byte then behaves three different ways: S-B lossy-decodes to U+FFFD and **silently changes the derived key** (`crypto.rs:38-44`, whose own comment says "which would change the derived key"), S-C uses it raw and round-trips correctly, S-D hard-errors `Bip39Error::PassphraseNotUtf8` (`bip39.rs:187`). Architecture must decide explicitly whether `FileSource` validates UTF-8 at the boundary — making all three fail closed, matching S-D — or preserves each consumer's current behavior. Leaving it implicit is not acceptable; the silent one is S-B. The pre-existing three-way divergence is **out of scope to fix**. |

**Why FR-8 preserves today's behavior rather than changing it.** The repo's own verification
workflow already funnels a passphrase *file* into the env flag via command substitution —
`KEYSTORE_PASSPHRASE=$(cat testdata/hoodi/passphrase.txt)` (`.claude/skills/verify/SKILL.md:18`)
— and `$(...)` strips trailing newlines. Stripping one terminator keeps that workflow
byte-identical; **not** trimming would change it for any fixture that has a newline. (The
current fixture is 28 bytes with no trailing newline, so it is unaffected either way — but
the next one written with `echo` would be.)

**Citation note for the geth claim in FR-9.** go-ethereum has **more than one password-file
reader**. The body cited by R1 is `readPasswordFromFile` at `cmd/geth/accountcmd.go:226-240`;
the same three lines — `strings.Split(string(text), "\n")` then
`strings.TrimRight(lines[0], "\r")` with the comment `// Sanitise DOS line endings.` — appear
independently in `cmd/utils/flags.go` inside `SetEthConfig`, which is the copy **independently
verified** for this PRD. The semantics are identical at both sites; downstream stages should
cite `cmd/utils/flags.go` (verified) and may cite `accountcmd.go` alongside it, but must not
treat either file:line as the sole authority. Historically the shared helper was
`utils.MakePasswordList` (`cmd/utils/flags.go:1287-1302` at `v1.13.15`), which returns *every*
line because `--password` is by design a password **list** indexed per unlocked account.

### 4.3 What file the tool will read

| # | Pri | Requirement |
|---|---|---|
| **FR-13** | P0 | Missing, unreadable, or permission-denied → **exit 2**, message names the path and the OS error. Never the contents. |
| **FR-14** | P0 | A **directory** is exit 2, via an **explicit `is_dir()` check on the opened descriptor's metadata**. Measured: `File::open("/tmp")` *succeeds*; without the check the failure surfaces only at the first read as `Is a directory (os error 21)`, from a code path that looks like a read failure. A **FIFO or character device** is accepted — `<(...)` process substitution and `/dev/fd/N` are the recommended no-disk-file pattern (FR-6) and must work. |
| **FR-15** | P0 | Symlinks are **followed**. The decisive case is **Kubernetes**: every user-visible file in a projected Secret volume is a symlink to `..data/<key>`, which is itself a symlink to a timestamped directory (`pkg/volume/util/atomic_writer.go:50-133`). An implementation demanding a regular file from `symlink_metadata` would reject **every** Kubernetes-mounted secret, and one stat'ing the link rather than the target would read the wrong mode. (Docker Swarm's `/run/secrets/<name>` is the counter-shape: a plain regular file, 0444.) Implement as `File::open` then `File::metadata` — `fstat` on the open descriptor, following OpenSSH's `authfile.c:82-87` — so the mode checked, the type checked, and the bytes read are the same inode, TOCTOU-free. |
| **FR-16** | P0 | A size ceiling of **4 KiB** — 4× OpenSSL's `APP_PASS_LEN` of 1024, whose response to exceeding it is *silent truncation*, the worst possible outcome here since a truncated scrypt password is a silently different key. Over the ceiling → **exit 2, never truncate**. **The ceiling must be enforced as a read cap, not a stat cap:** `/dev/zero` reports `len() == 0` (measured), so a `metadata.len() > CAP` test never fires on the very input FR-16 names. A pipe's `len()` is likewise the currently-buffered byte count, not a length. The `metadata.len()` check may stay for regular files only, as an early and better-worded rejection — never as the sole enforcement and never as an allocation size. With FR-19b this gives a closed interval `[8, 4096]` for a keystore passphrase. |
| **FR-17** | P0 | On Unix, a **regular file** with `mode & 0o077 != 0` emits **one `WARNING:`-prefixed line to stderr** naming the path and the octal mode, and the run **continues**. Recommended wording (R3): `WARNING: file permissions 0644 for "<path>" are too open; the secret is readable by group or other. Fix with: chmod 600 "<path>"`. **The "regular file" scoping is load-bearing, not cosmetic:** a `<(...)` process-substitution pipe is mode **0440** (measured), so without the scoping the *recommended* no-disk-file pattern would emit a WARNING on every single run and collide with FR-21. See the note below and **OD-4**. |
| **FR-18** | P0 | **Empty-file semantics mirror today's env semantics exactly.** `--mnemonic-passphrase-file` pointing at an empty file (0 bytes, or a lone terminator) is a **valid empty passphrase** — today's `Env` form accepts an empty value and rejects only *unset* (`keystore_cli.rs:130-143`). `--passphrase-file` pointing at an empty file is **exit 2** via a typed error mirroring `KeystoreError::EnvVarEmpty` (`passphrase.rs:58`). |
| **FR-19** | P0 | The `is_posix_env_var_name` footgun guard is re-derived, not deleted: if `--private-key-file` names a path that does not exist **and** the argument matches `^(0x)?[0-9a-fA-F]{64}$`, exit 2 with "that looks like a key value, not a path" — **without echoing the argument**. |
| **FR-19b** | P0 | **The 8-byte keystore-passphrase minimum survives the move.** `KEYSTORE_PASSPHRASE_MIN_LEN` is not enforced inside `EnvSource`; it is applied at the call site by the `MinLenPassphrase` decorator (`keygen.rs:215-225`) wrapping the source, at `validator_cmd.rs:98`/`:159` and `account_cmd.rs:103`/`:159`. `FileSource` must be wrapped identically, so a short passphrase file still yields `KeystoreError::PassphraseTooShort` (exit 2). Length is measured by `require_min_len` on the **EIP-2335-normalized** form (`passphrase.rs:173`) of the bytes remaining **after** FR-8 stripping — a 7-character passphrase plus a trailing `\n` is 8 raw bytes and must still fail. |
| **FR-20** | P1 | The user guide gains an explicit warning, in the same register as the existing raw-`--mnemonic-passphrase` warning (`USER-GUIDE.md:237`), that a *passphrase* mistakenly passed where a *path* is expected lands in argv, `ps`, shell history, and the not-found error message. There is no shape to key on for a passphrase, so documentation is the mitigation. |

**Note on FR-17 (warn, not reject).** Git cannot store mode 0600 — it tracks only the
executable bit, and `git ls-files -s testdata/hoodi/passphrase.txt` reports `100644`. Any
passphrase fixture checked into this repo is therefore necessarily group/other-readable, so a
hard reject would break the repo's own `verify` skill on its own fixture. Warning also matches
the existing precedent for a security-relevant-but-not-fatal condition
(`warn_if_symlinked_output_dir`, `fs_util.rs`). The counter-argument is genuinely strong and
recorded as **OD-4**: this tool writes every secret it produces at 0600 via `write_new_0600`
(`fs_util.rs:87`), so refusing to *read* at anything looser is consistency with its own output.

| # | Pri | Requirement |
|---|---|---|
| **FR-21** | P1 | The FR-17 warning must not break the three assertions that count `WARNING` lines and require **exactly one**: `validator_cli.rs:543-548` (symlinked output dir), `validator_e2e.rs:495-499` (`--no-verify`), and `validator_e2e.rs:526-530` (symlink e2e). Each must become warning-**kind**-specific — not loosened to "at least one". R3 supplies the discriminating token: **`file permissions`**, which appears in no other message, is not a flag name (so it survives a flag rename), and is not a path (so it is host-independent). |

### 4.4 Read-once, and the lost zero-flag default

| # | Pri | Requirement |
|---|---|---|
| **FR-22** | P0 | **The private key file is read exactly once per invocation.** In **RPC mode specifically** — the branch is gated on `cfg.signer == "local" && !cfg.build.rpc_url.is_empty()` (`run_cmd.rs:164`) — `tx run` constructs a `LocalSigner` to derive `from` (`run_cmd.rs:165`), then passes the same identifier into `SignConfig` (`run_cmd.rs:193`) and `sign_unsigned_tx` constructs a **second** signer (`sign_cmd.rs:174`). Without `--rpc-url` there is only one construction, so the defect is invisible outside RPC mode — do not conclude from a non-RPC run that it is already fine. Two reads are free with an env var and **measured fatal** otherwise: the second read of a `<(...)` path returns **zero bytes**, and the second open of a named `mkfifo` FIFO **blocks indefinitely**. This cannot be softened into a better error message — for the FIFO there is no error to report, only a hung ceremony. The material (or an in-process source, mirroring `InMemoryPassphrase`, `keystore_cli.rs:170`) must be passed forward, not the path. Same discipline for `--passphrase-file` wherever a passphrase source is consulted twice. |
| **FR-23** | P0 | Secret file contents are read into a **single fixed 4097-byte `Zeroizing<Vec<u8>>` filled by an explicit read loop** — allocated once, never grown, never reallocated; short reads retried on `Interrupted`; `truncate(n)` at the end (safe: `zeroize` zeroes spare capacity too). The requirement's premise is confirmed by `zeroize` 1.9.0's own doc comment — *"Ensures the entire capacity of the `Vec` is zeroed. **Cannot ensure that previous reallocations did not leave values on the heap.**"* (`src/lib.rs:520-538`) — so `fs::read_to_string` / `fs::read` / any growing `Vec` leaves un-zeroized copies of the secret behind. GnuPG solves this with a wiping allocator (`xmalloc_secure`); with zero new dependencies (M-4) "never reallocate" is the equivalent, and simpler. **A fixed buffer rather than "allocate from the known length": one code path for regular files, FIFOs and character devices, and TOCTOU-proof** — the length is *unavailable* for `/dev/zero` (reports 0) and *a lie* for a pipe (reports currently-buffered bytes). The 4097th byte is the FR-16 overflow sentinel. **Citation correction:** this is *not* the pattern `RecoverMnemonicSource` uses — `keygen.rs:350-353` is `Zeroizing::new(String::new())` + `read_to_string`, which grows and reallocates. FR-23 is *stricter* than any existing path. The pre-existing piped-stdin residue in `keygen.rs` is a **deliberate out-of-scope omission**, recorded here so a reviewer does not mistake it for a regression introduced by this work. |
| **FR-23b** | P1 | The `PassphraseSource::read` trait boundary hands back a plain `Vec<u8>` and its own doc comment calls the re-wrap a "secret-residue footgun" (`passphrase.rs:26-34`). `FileSource` must build that return with `Vec::with_capacity(n)` + `extend_from_slice`, so the boundary copy also never reallocates, and drop its internal `Zeroizing` buffer immediately. Callers already re-wrap (`MinLenPassphrase::read`, `keygen.rs:224`; `KeyLoader::load`) — which is a second reason FR-19b's decorator wrapping is mandatory: it is a hygiene requirement as well as a length requirement. |
| **FR-24** | P0 | **`--private-key-file` is required when `--signer local`** on both `tx sign` and `tx run`; absent → exit 2 naming the flag. This is a deliberate UX regression: `--private-key-env` has `default_value(DEFAULT_PRIV_KEY_ENV)` (`sign_cmd.rs:85`), so `ethernal tx sign --signer local` works today with no key flag at all when `ETHERNAL_TX_PRIVATE_KEY` is set. There is no defensible default *path*. See **OD-5** for the alternative. |
| **FR-25** | P1 | `DEFAULT_PRIV_KEY_ENV` (`sign_cmd.rs:19`) is removed along with the flag it defaulted. |

### 4.5 Library API and the inverted security invariant

| # | Pri | Requirement |
|---|---|---|
| **FR-26** | P0 | `FileSource` is added beside `EnvSource` (`passphrase.rs:37`) and `new_local_signer_from_file` beside `new_local_signer_from_env` (`local.rs:119`), both re-exported (`ethernal-keystore/src/lib.rs:26`, `ethernal-signer/src/lib.rs:21`). The env-based items are **retained** — they are public API and their removal is a separate decision (**OD-6**). |
| **FR-27** | P0 | `FileSource` implements FR-8/FR-13/FR-16/FR-17 itself so every call site inherits the same rules, and returns typed `KeystoreError` variants for not-found / empty / multi-line / too-large. Exit-code mapping is asserted explicitly in `errors.rs` tests (the `_ => 2` catch-all at `errors.rs:292` would silently absorb them otherwise; see the `EnvVarEmpty` assertion at `errors.rs:534` for the pattern). |
| **FR-28** | P0 | **The doc comments that name env as *the* secure source are rewritten.** `local.rs:70-73` states the key "MUST come from a secure source (environment variable...)" and "MUST NEVER appear in argv"; `local.rs:85` says "Prefer `new_local_signer_from_env` in CLI code so the key never appears in argv". After this change the CLI's source is a file whose *path* appears in argv. Ship without this rewrite and the code contradicts its own documentation. |
| **FR-29** | P0 | `KeystoreError::NoTty`'s message hard-codes a flag that will no longer exist: "supply the passphrase via `--passphrase-env VAR`" (`error.rs:68`), asserted by substring at `passphrase.rs:307`. It must name `--passphrase-file PATH`. Same for the two `--mnemonic-passphrase-env VAR` strings in `keygen.rs:289` and `:389`. |
| **FR-30** | P1 | Help text that describes the local signer as env-based is corrected: `--signer` help "local (env-var private key)" (`sign_cmd.rs:65`, `run_cmd.rs:69`) and the `long_about` block at `sign_cmd.rs:46-49`, whose "The key must never appear in CLI arguments or shell history" needs restating for a path argument. |

### 4.6 Secret hygiene tests — extended, not renamed

Mechanically swapping flag strings in the test suite would leave the *new* leak vectors
untested. File mode adds two the env path did not have: an error that echoes file **contents**,
and a not-found error that echoes an argument the user may have mistakenly made the secret.

| # | Pri | Requirement |
|---|---|---|
| **FR-31** | P0 | `validator_secret_hygiene.rs`, `account_secret_hygiene.rs`, and `redact_boundary.rs` gain assertions that file **contents** appear in no stdout/stderr/log/`Debug` output, on every error path: not found, permission denied, is-a-directory, empty, multi-line, over-size, bad hex, wrong passphrase. |
| **FR-32** | P0 | A test asserts the FR-19 guard does not echo the hex-shaped argument it rejects. |
| **FR-33** | P1 | A read-once test (FR-22) drives `tx run --signer local` with a FIFO path and asserts success — the regression it guards is invisible to a regular-file test. |
| **FR-34** | P1 | `exit_usage.rs` gains cases for each new exit-2 path, and asserts the removed `-env` flags are now unknown flags (FR-1). Existing **help-text** assertions that require the old flag names to be present — e.g. `help.contains("--mnemonic-passphrase-env")` at `validator_e2e.rs:440-443` — must be repointed to the new names; they fail on FR-2 otherwise. |
| **FR-35** | P1 | The test-harness env allowlist (`tests/common/mod.rs:48-53`) is reviewed: `ETHERNAL_TX_PRIVATE_KEY` no longer needs scrubbing, the `ETHERNAL_TX_RPC_URL`/`_FROM`/`_GAS_LIMIT` entries stay (assumption A-1). |

### 4.7 Documentation

| # | Pri | Requirement |
|---|---|---|
| **FR-36** | P0 | `docs/USER-GUIDE.md` (53 occurrences), `README.md` (2), and `.claude/skills/verify/SKILL.md` (3) are updated. Every `export VAR=secret` example becomes a file example that does **not** create a world-readable file — i.e. shows `umask 077` or `chmod 600`, or uses process substitution. |
| **FR-37** | P0 | `CHANGELOG.md` records this as a **breaking change** under a `### Removed` heading listing all three flags by name, with the migration line for each, and states the FR-24 regression explicitly. |
| **FR-38** | P1 | The user guide's "two passphrases are never interchangeable" section (`USER-GUIDE.md:197-200`) is re-written for files, and gains the FR-8 byte rule. |

## 5. Non-goals

- **The `ETHERNAL_TX_*` value fallbacks stay.** `--rpc-url`, `--from` and `--gas-limit` read
  `ETHERNAL_TX_RPC_URL` / `_FROM` / `_GAS_LIMIT` when the flag is absent (`build_cmd.rs:101`,
  `:106`, `:129`; `send_cmd.rs:76`). These are not flags that take an env var name — the flag
  takes a real value and env is a fallback *source*, and none of the three values is a secret.
  See **OD-1**.
- No removal of `EnvSource` or `new_local_signer_from_env` from the library (**OD-6**).
- No new flag for relaxing the permission policy (**OD-4**).
- No change to keystore formats, filenames, output permissions, write semantics, scrypt
  parameters, or the C1–C4 verification work merged in `docs/plan/keygen-progress-verify/`.
- No secret-manager integrations (Vault, AWS SM, `pass`). Process substitution (FR-14) is the
  supported bridge to all of them.
- No attempt to zeroize the secret **file on disk** — outside the tool's control, and the
  reason FR-14 exists.
- **No fix for the three-way non-UTF-8 divergence** between S-B, S-C and S-D (FR-12b). It is
  pre-existing; this change only makes it *reachable*, and FR-12b requires architecture to pick
  a boundary policy consciously rather than to repair the consumers.
- **No fix for the pre-existing piped-stdin residue** in `RecoverMnemonicSource`
  (`keygen.rs:350-353`, `Zeroizing::new(String::new())` + `read_to_string`, which reallocates).
  Recorded as a deliberate omission under FR-23 so it is not mistaken for a regression
  introduced here.

## 6. Assumptions

1. **A-1 — the `ETHERNAL_TX_*` fallbacks are out of scope** (§5, **OD-1**).
2. **A-2 — CLI surface only.** `EnvSource` and `new_local_signer_from_env` are public library
   API and are retained; `FileSource` / `new_local_signer_from_file` are added alongside
   (FR-26). Only the *flags* are removed.
3. **A-3 — breaking change, no deprecation window.** No release of this tool has shipped a
   deprecation policy, and a silently-still-working `--passphrase-env` is worse than a loud
   unknown-flag error for a secret-handling flag. Recorded in `CHANGELOG.md` as breaking
   (FR-37). **OD-6** carries the alternative.
4. **A-4 — Unix only for FR-17.** The permission check is `#[cfg(unix)]`, matching the
   existing `write_new_0600` / `look_path` mode handling.

## 7. Open Decisions

**OD-1, OD-4 and OD-5 were resolved by the user at the PRD review gate on 2026-07-25**; each
confirmed the assumption the PRD had already taken, so no requirement changed. **OD-2, OD-3 and
OD-7 were resolved at the research review gate on 2026-07-25** — unlike the first three, OD-2
and OD-7 **changed requirements** (FR-8 narrowed, FR-9 widened, FR-12 extended). All six are
kept here with their resolution recorded.

**OD-6 remains the one open decision** and is handed explicitly to the architecture stage: the
research charter gathered no evidence on it.

| # | Decision | Assumed | If the other reading wins |
|---|---|---|---|
| **OD-1** ✅ **RESOLVED — fallbacks stay** | Do the `ETHERNAL_TX_RPC_URL`/`_FROM`/`_GAS_LIMIT` fallbacks stay? | **Yes** — they take values, not variable names, and hold no secrets. Confirmed by the user; §5 and A-1 stand. | (Moot.) Scope would have grown by three more flags plus their fallback plumbing. |
| **OD-2** ✅ **RESOLVED — strip one `\n`, reject every `\r`** | Trim rule for the two **raw** consumers, S-C (v3 keystore) and S-D (mnemonic seed). | **Strip exactly one trailing `\n`; any residual `\r` or `\n` is exit 2** (FR-8 + FR-9 as amended). The original "strip one terminator, `\n` or `\r\n`" reading **did not survive the evidence**: it accepted `pw\r` and `pw\r\r\n` — which FR-9 could not catch, no `\n` remaining — and derived a **different v3 key from the same file than geth**, and it picked an unwitnessed side on `pw\r\n`. | **The user ruled at the research gate**, choosing *reject any CR* over the available fallback of *accept CRLF and strip it* (geth-matching, so Windows-authored files would work without `dos2unix`) — on the grounds that the three surveyed tools disagree about CRLF and **refusing is the reversible direction**: refusing can be relaxed to stripping later without invalidating any key already created; the converse is false. Note the fallback would still have required FR-9's widening, since bare and doubled CRs are unhandled either way. Two further alternatives were declined: `TrimRight` all CRs (geth-exact, but locks geth's reading in against OpenSSL's and gpg's) and no trim at all (makes `echo pw > f` silently wrong for S-D). |
| **OD-3** ✅ **RESOLVED — exit 2, and it stays reversible** | Multi-line file. | **Exit 2** (FR-9). The strict-subset argument was **tested against geth's actual body** and holds for every file containing no `\r`: `Split(text,"\n")[0]` yields byte-identical output to FR-8 for `pw` and `pw\n`, as do OpenSSL and gpg. It failed **only** in the CR rows, which the OD-2 amendment closes — so with FR-9 widened, the accepted set contains no CR at all and the subset property holds against all three tools without exception. | (Moot.) *First-line-wins* can still be adopted later without invalidating anything, which is precisely why deferring it costs nothing. One documentation consequence: FR-9 is a **deliberate divergence, not a parity claim** — geth accepts multi-line files because `--password` is a password *list* indexed per unlocked account (`MakePasswordList` + `GetPassPhraseWithList`), a feature ethernal does not have. FR-11 requires the guide to say so. |
| **OD-4** ✅ **RESOLVED — warn, continue** | World/group-readable file (`mode & 0o077 != 0`). | **Warn, continue** (FR-17), grounded in git's inability to store 0600. Confirmed by the user; FR-17 and FR-21 stand as written. | (Moot.) *Hard reject* was the security-consistent reading (the tool writes at 0600, `fs_util.rs:87`), at the cost of breaking the `verify` skill on its own tracked fixture. The `--insecure-file-permissions` escape-hatch variant was also declined — it adds a flag to a change whose purpose is removing them. |
| **OD-5** ✅ **RESOLVED — mandatory flag** | The lost zero-flag default for `tx sign --signer local`. | **`--private-key-file` becomes mandatory** (FR-24). Confirmed by the user: the regression is accepted deliberately, and no secret source may be implicit. | (Moot.) *`ETHERNAL_TX_PRIVATE_KEY_FILE` as a **path** fallback* would have preserved zero-flag operation. **Explicitly declined** — do not reintroduce it in architecture or issues, and do not infer it from OD-1's "fallbacks stay". Any CI job relying on the zero-flag path must be updated (FR-37). |
| **OD-6** ⏳ **OPEN — handed to architecture** | Deprecation window, and the fate of the env library API. | **No window; flags removed at once. Library `EnvSource` / `new_local_signer_from_env` retained** (A-3, A-2). | Research gathered **no evidence** on this — it was outside the charter — so the assumption stands unvalidated and the architecture stage owns it. *One release with the `-env` flags `.hide(true)` + a deprecation warning* softens the break for anyone scripting against `develop`, at the cost of shipping both code paths and both sets of hygiene tests. Separately: if the library env sources are also to go, that is a semver-major decision needing its own disposition. |
| **OD-7** ✅ **RESOLVED — no as written; yes as amended** | Does the FR-8 rule hold for the **v3/geth parity** case (S-C)? | **No, as originally written — yes with the OD-2 amendment.** geth passes the password string raw into scrypt (`EncryptKey` → `EncryptDataV3(…, []byte(auth), …)` → `scrypt.Key`, `accounts/keystore/passphrase.go:184-186`, `:145`), confirming `encrypt_v3.rs:150` from source: every byte the file layer keeps changes the key. Concretely, for `hunter2hunter2\r`, the original FR-8 encrypted under 15 bytes while geth derived from 14 — one file, two v3 keys, and `cat` renders them identically (only `xxd` distinguishes them), so the operator has no local means of diagnosing it. **With FR-8+FR-9 as amended, ethernal's bytes equal geth's for every file the rule accepts.** | (Moot — FR-10's "one rule everywhere" is preserved, since the amendment applies uniformly.) |

**Consequences for the two open manual parity gates.** Both must be extended before release:

- **H9** (validator) and **A5-M** (EOA) each gain a **bare-CR case** (`pw\r`) and a **CRLF case**
  (`pw\r\n`), both asserting **exit 2**. These are the only rows where the two implementations
  can disagree, so they are the only rows the gates must exercise beyond the plain case.
- **A5-M** additionally round-trips against real geth on the plain cases:
  `geth account import --password <file>` against an ethernal-written v3 keystore from that same
  file, and `ethernal account recover --passphrase-file <file>` against one geth wrote — for a
  file with and without a trailing `\n`. FR-12 is the automated equivalent, not a replacement.

## 8. Acceptance

The feature is done when, on `develop`:

- `make lint && make test` are green, and `rg -- '--(passphrase|private-key|mnemonic-passphrase)-env'`
  over `bins/`, `crates/`, `docs/`, `README.md` and `.claude/skills/` — excluding `CHANGELOG.md`,
  whose FR-37 migration lines name the removed flags by design — returns no flag definitions or
  usage examples.
- For each of S-B, S-C and S-D, a secret file with a trailing newline and one without produce
  identical derived output (FR-12), and the S-D case matches the `--mnemonic-passphrase VALUE`
  form.
- For S-C and S-D, files containing `pw\r`, `pw\r\n` and `pw\r\r\n` **each exit 2** (FR-9/FR-12).
  These three rows are the only automated evidence the widened residual check is live — a suite
  without them passes under the superseded rule.
- `tx run --signer local --rpc-url <stub> --private-key-file <(printf '%s' "$KEY")` succeeds —
  RPC mode is required, since that is the only path that constructs two signers (FR-22).
- A named `mkfifo` FIFO supplied to `--private-key-file` in the same RPC-mode run completes
  rather than hanging (FR-22 — the measured failure is an indefinite block, not an error).
- A passphrase file holding 7 characters plus a trailing newline exits 2 with
  `PassphraseTooShort`, not success (FR-19b).
- `tx sign --signer local` with no key flag exits 2 naming `--private-key-file` (FR-24).
- A 0644 passphrase file warns exactly once, with the token `file permissions`, and completes;
  a `<(...)` process-substitution path in the same run emits **no** permission warning despite
  being mode 0440 (FR-17).
- A **directory** path exits 2 with FR-14's intended message, not `Is a directory (os error 21)`.
- `--passphrase-file /dev/zero` exits 2 (FR-16 — it reports `len() == 0`, so only a read cap
  catches it), and an empty file, a multi-line file and an over-size regular file each exit 2
  without echoing any content.
- No error path anywhere prints file contents (FR-31), and `--private-key-file 0x<64 hex>`
  is rejected without echoing the argument (FR-32).
- `local.rs` no longer documents an environment variable as the required secure source (FR-28),
  and `KeystoreError::NoTty` names a flag that exists (FR-29).

---

**Revision history.** Amended 2026-07-25 after the research review gate: FR-8 narrowed to a
single trailing `\n`, FR-9 widened to reject every residual `\r`/`\n` (user's ruling), FR-12
extended with the CR rows, FR-12b and FR-23b added, and FR-14/15/16/17/22/23 re-grounded on
measured evidence. OD-2, OD-3 and OD-7 resolved; OD-6 remains open.

**Upstream:** [`research/index.md`](research/index.md) ·
[`research/r1-secret-file-line-endings.md`](research/r1-secret-file-line-endings.md) ·
[`research/r2-file-reading-policy.md`](research/r2-file-reading-policy.md) ·
[`research/r3-permission-warning.md`](research/r3-permission-warning.md)
**Downstream:** `architecture.md` · `project-plan.md` · `issues/index.md`
