# Research index — env-var-name flags → file-path flags

Three questions. R1 was answered from the source of geth, OpenSSL, GnuPG and
staking-deposit-cli; R2 and R3 from source plus measurements run on this host.

| # | Question | Verdict | File |
|---|---|---|---|
| **R1** | What do comparable tools do with line endings in a secret file? | geth is **first-line-wins + `TrimRight(line, "\r")`**; OpenSSL and gpg are first-line-wins and **keep `\r`**; clef and deposit-cli have **no password-file option at all**. FR-8 agrees with geth on `pw` and `pw\n`, silently diverges on `pw\r`/`pw\r\r\n`, and picks an unwitnessed side on `pw\r\n` → **refuse every `\r`** | [`r1-secret-file-line-endings.md`](r1-secret-file-line-endings.md) |
| **R2** | File-reading policy prior art | 4 KiB is sane (OpenSSL's is 1 KiB and it **truncates silently**); follow symlinks — every K8s secret is one; FR-23's premise is confirmed by `zeroize`'s own doc comment, but the **recipe should change** to a fixed 4097-byte buffer; read-once defect measured and real | [`r2-file-reading-policy.md`](r2-file-reading-policy.md) |
| **R3** | Permission-warning wording (OD-4 already resolved — not reopened) | Take OpenSSH's mask, `fstat`-on-fd, and octal-plus-path wording; skip its `@@@@` banner and its `st_uid == getuid()` guard; **token `file permissions`** for FR-21 | [`r3-permission-warning.md`](r3-permission-warning.md) |

## Recommendations on the open decisions

| # | Recommendation | The evidence that decides it |
|---|---|---|
| **OD-2** — trim rule for the raw consumers (S-C, S-D) | **Strip exactly one trailing `\n`, and widen FR-9 to reject any `\r` or `\n` remaining anywhere in the result.** Two clauses: FR-8 loses its `\r\n` alternative, FR-9's residual check widens from `\n` to `\n`-or-`\r`. A CRLF file becomes exit 2. | geth `readPasswordFromFile` (`cmd/geth/accountcmd.go:226-240`) is first-line-wins **plus `strings.TrimRight(lines[0], "\r")`**; OpenSSL (`apps/lib/apps.c:295-306`) and gpg (`g10/passphrase.c:149`) are first-line-wins and **keep the `\r`**. So on `pw\r` and `pw\r\r\n` — which FR-9 does not catch, no `\n` remaining — FR-8-as-written derives a **different v3 key from the same file than geth does**; and on `pw\r\n` the three tools disagree with *each other*, so accepting it hard-codes one reading into a derived key. Rejecting every CR is the only rule under which ethernal's bytes equal all three tools' bytes for every accepted file, and it is the only choice that stays reversible (refusing CRLF can be relaxed later; accepting it cannot be undone). The discriminating principle — **strip what all tools call a terminator, keep what all tools call content, refuse what they disagree about** — is also what makes FR-11's keep-the-trailing-space rule consistent rather than arbitrary. For **S-D** there is **no prior art at all** (no surveyed tool offers a mnemonic-passphrase file), so it rests on the silent-failure argument (`bip39.rs:181-201`: no control strip, no trim; C1–C4 cannot detect a wrong seed) plus FR-10. **Pre-empting an M-1 objection:** refusing a CR file where the env path would have derived a key is not a *differing* key — M-1 counts keys that differ, and exit 2 produces none. **Single fallback if the gate wants Windows-authored files to work without `dos2unix`:** keep FR-8's `\r\n` clause (accept CRLF, strip it, matching geth but not OpenSSL/gpg) — the FR-9 widening is still required either way, since it is what catches bare and doubled CRs. |
| **OD-3** — multi-line file | **Keep exit 2 (FR-9), widened as above.** | The PRD's strict-subset argument was tested against geth's actual body and **holds for every file containing no `\r`**: geth's `Split(text,"\n")[0]` yields byte-identical output to FR-8 for `pw` and `pw\n`, as do OpenSSL and gpg — so FR-9 can be relaxed to first-line-wins later without invalidating any key already created. It **fails only** in the `\r` rows, which the OD-2 amendment closes. Also: geth accepts multi-line files because `--password` is a password **list** indexed per unlocked account (`MakePasswordList` + `GetPassPhraseWithList`, v1.13.15) — FR-9 is a deliberate divergence from a feature ethernal does not have, not a parity claim. |
| **OD-7** — does FR-8 hold for the v3/geth parity case (S-C)? | **No as written; yes with the OD-2 amendment.** | `EncryptKey` → `EncryptDataV3(…, []byte(auth), …)` → `scrypt.Key(auth, …)` (`accounts/keystore/passphrase.go:184-186`, `:145`) — geth passes the string raw, confirming `encrypt_v3.rs:150` from source. So every byte the file layer keeps changes the key. With the amendment, ethernal's bytes equal geth's bytes for **every file the rule accepts**. **H9 and A5-M must each gain a bare-CR case and a CRLF case, both asserting exit 2**, and A5-M must round-trip a real `geth account import --password <file>` against an ethernal-written v3 keystore from the same file, with and without a trailing `\n`. |
| **OD-1, OD-4, OD-5** | Already resolved by the user; not revisited. R3 supplies only the warning wording for OD-4. | — |
| **OD-6** | **Outside this charter.** No evidence gathered; the deprecation-window and library-API decision remains open for the architecture stage. | — |

## Findings that should change the PRD

1. **FR-9 must widen from `\n` to any line-terminator byte, and FR-8 must drop its `\r\n`
   alternative.** This is the whole result of R1. A trailing `\r` with no `\n` passes FR-8 and
   FR-9 today and silently forks the derived key from geth's; a CRLF file is decoded three ways by
   the three surveyed tools. Two clauses, P0. ([`r1`](r1-secret-file-line-endings.md) §3.1, §5)
2. **FR-12 must gain the CR cases, or the amendment ships untested.** FR-12 today asks only that a
   file with a trailing `\n` and one without produce identical output — a suite that passes under
   FR-8-as-written with zero CR coverage. Per consumer, for **S-C and S-D** (the two live ones, by
   FR-12's own argument about S-B): (a) `pw` and `pw\n` produce identical output — already
   required; (b) `pw\r`, `pw\r\n` and `pw\r\r\n` each **exit 2**. Those three rows are the only
   automated evidence the new clause is live.
3. **FR-23's recipe should change, though its requirement should not.** `zeroize`'s own doc
   comment — *"Ensures the entire capacity of the `Vec` is zeroed. Cannot ensure that previous
   reallocations did not leave values on the heap"* (`zeroize-1.9.0/src/lib.rs:520-538`) —
   confirms the no-realloc requirement **and** that spare capacity is covered, so a single fixed
   4097-byte `Zeroizing<Vec<u8>>` filled by an explicit read loop is better than "allocate from
   the known length": one code path for regular files, FIFOs and character devices, and
   TOCTOU-proof. The known length is *unavailable* for `/dev/zero` (reports 0) and a *lie* for a
   pipe (reports currently-buffered bytes — measured 6). ([`r2`](r2-file-reading-policy.md) §1.2,
   §3)
4. **FR-16's ceiling must be a read cap, not a stat cap.** `/dev/zero` reports `len() == 0`, so a
   `metadata.len() > CAP` test never fires on the very input FR-16 names.
   ([`r2`](r2-file-reading-policy.md) §1.2)
5. **FR-23 cites a precedent that does not exist.** `RecoverMnemonicSource` uses
   `Zeroizing::new(String::new())` + `read_to_string` (`keygen.rs:350-353`) — Zeroizing from the
   first allocation, but it grows and reallocates. FR-23's technique is *stricter* than its cited
   precedent; the citation should be corrected, and the pre-existing stdin residue recorded as a
   deliberate out-of-scope omission. ([`r2`](r2-file-reading-policy.md) §3.4)
6. **FR-14 needs an explicit `is_dir()` check.** Measured: `File::open("/tmp")` **succeeds**; the
   failure only appears at the first `read` as `Is a directory (os error 21)`, from a code path
   that looks like a read failure. ([`r2`](r2-file-reading-policy.md) §5)
7. **FR-17's "regular file" scoping is load-bearing, not cosmetic.** A `<(...)` pipe is mode
   **0440** — without that scoping the *recommended* no-disk-file pattern would emit a WARNING on
   every run and collide with FR-21. ([`r2`](r2-file-reading-policy.md) §4)
8. **FR-15's justification should cite Kubernetes, not `pass`.** Every user-visible file in a K8s
   projected Secret volume is a symlink into `..data/<key>`
   (`pkg/volume/util/atomic_writer.go:50-133`). `pass` has no file interface at all — `pass show`
   writes to stdout, so it is a process-substitution example, not a symlink one.
   ([`r2`](r2-file-reading-policy.md) §2)
9. **FR-22 is worse than the PRD states.** Measured: the second read of a `<(...)` path returns
   **zero bytes**; the second open of a **named FIFO blocks indefinitely**. The read-once fix
   cannot be softened into a better error message — for `mkfifo` there is no error, only a hung
   ceremony. ([`r2`](r2-file-reading-policy.md) §4)
10. **A new asymmetry the PRD's §4.2 table does not name.** An env var could not carry non-UTF-8
   bytes; a file can. The same invalid byte then behaves three ways: S-B lossy-decodes to U+FFFD
   and **silently changes the derived key** (`crypto.rs:38-44`), S-C uses it raw and correctly,
   S-D hard-errors `PassphraseNotUtf8`. Pre-existing and out of scope to fix, but architecture
   should decide consciously whether `FileSource` validates UTF-8 at the boundary.
   ([`r1`](r1-secret-file-line-endings.md) §3.4)
11. **S-B is unconstrained, and the PRD can stop worrying about it.** `staking-deposit-cli` has no
    password-file option — its only non-interactive path is `--keystore_password` in argv, the
    exposure this change exists to remove — and its `_process_password` (`keystore.py:119-126`) is
    byte-for-byte `normalize_passphrase`. Every candidate rule gives the same v4 result.
    ([`r1`](r1-secret-file-line-endings.md) §1.5, §3.2)
12. **Nothing found argues against the flag change itself.** OpenSSL treats `file:` and `env:` as
    equal peers; geth, gpg and clef offer no `env:`-name form at all. The `-env`-name flag shape
    this PRD removes has **no prior art** in any tool surveyed.

## What is deliberately unlike prior art, and should be documented as such

| Behavior | Us | Them | Why |
|---|---|---|---|
| Multi-line file | exit 2 | geth: first line wins (it is a password *list*); OpenSSL/gpg: first line wins | Predictability; reversible later (OD-3) |
| CRLF file | exit 2 | geth: `pw`; **OpenSSL/gpg: `pw\r`** | The three tools disagree with each other, so any acceptance hard-codes one reading into a derived key. Refusing is the reversible direction |
| Any other `\r` | exit 2 | geth: strips all trailing CRs; OpenSSL/gpg: keep them | Same disagreement, plus FR-8-as-written matched none of them |
| Over-size file | exit 2 | OpenSSL: **silent truncation** at 1023 bytes | A truncated scrypt password is a silently different key |
| Empty file | mnemonic passphrase: valid empty · keystore passphrase: exit 2 | geth: empty password accepted; OpenSSL: error | Mirrors today's env semantics exactly (FR-18); not a parity claim |

**Downstream:** [`../architecture.md`](../architecture.md) · PRD §4.2, §4.3, OD-2, OD-3, OD-7
