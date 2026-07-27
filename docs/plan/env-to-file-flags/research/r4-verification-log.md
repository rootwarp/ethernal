# R4 — independent verification log

Claims from R1 and R2 that the team lead re-checked against primary sources and by
measurement, before the architecture stage acted on them. Recorded because FR-8/FR-9,
FR-14, FR-16, FR-22 and FR-23 are all P0 and rest on these facts.

**Host:** darwin 25.5.0 (macOS), `bash`, `python3`. Measurements are Unix but **not
Linux** — see §3 note.

## 1. Upstream source — verified

| Claim | Verdict | What was actually read |
|---|---|---|
| geth is first-line-wins **and strips all trailing CRs** | **Confirmed** | `cmd/utils/flags.go`, in `SetEthConfig`: `if lines := strings.Split(string(text), "\n"); len(lines) > 0 { passphrase = strings.TrimRight(lines[0], "\r") // Sanitise DOS line endings. }` |
| OpenSSL is first-line-wins and **keeps the CR** | **Confirmed** | `apps/lib/apps.c`, `app_get_pass`: reads with `BIO_gets(pwdbio, tpass, APP_PASS_LEN)`, then `tmp = strchr(tpass, '\n'); if (tmp != NULL) *tmp = 0;` — truncates at the first `\n`; nothing touches `\r`. |

**Consequence, restated from the verified bytes.** A CRLF file yields `pw` under geth and
`pw\r` under OpenSSL. The two tools disagree, so any rule that *accepts* CRLF necessarily
hard-codes one of them into a derived key. This is what decided OD-2.

**Citation correction.** R1 attributes geth's logic to `readPasswordFromFile` at
`cmd/geth/accountcmd.go:226-240`. That location was **not** verified; the semantics were
confirmed at `cmd/utils/flags.go` (`SetEthConfig`) instead. geth has more than one
password-file reader. Downstream documents must cite the verified location. The semantic
claim — first-line-wins plus `TrimRight(…, "\r")` — is unaffected.

## 2. Measured behavior — confirmed

| # | Claim | Measured |
|---|---|---|
| M-a | `/dev/zero` reports length 0, so a stat-based cap never fires | `os.stat('/dev/zero').st_size == 0` ✅ |
| M-b | `File::open` on a directory succeeds; failure only appears at first read | `os.open('/tmp', O_RDONLY)` → fd 3; `os.read(fd, 10)` → `OSError [Errno 21] Is a directory` ✅ |
| M-c | Second read of a `<(...)` path returns zero bytes | `read1 = b'secret123'`, `read2 = b''` ✅ |
| M-d | Second open of a **named FIFO blocks indefinitely** | `timeout 5 …` → **exit 124**. No error, no EOF — a hung ceremony ✅ |
| M-e | A `<(...)` pipe is mode 0440, so FR-17's regular-file scoping is load-bearing | `mode = 0o440`, `S_ISFIFO = True` ✅ |

## 3. One finding stronger than R2 reported

R2 says a pipe's `st_size` is "a lie (reports currently-buffered bytes — measured 6)".
Measured here on a 9-byte payload: `st_size = 9`. So the value is not a constant 0 that a
cap could special-case — it is **an arbitrary snapshot of whatever happens to be buffered at
the moment of the call**, and it varies with writer timing.

This makes FR-16's amendment (read cap, not stat cap) load-bearing for a second, independent
reason beyond `/dev/zero`: on a pipe a stat-based cap does not merely fail to fire, it fires
*nondeterministically*. Two runs of the same command with the same input can disagree. A
fixed-buffer read loop (FR-23) is the only approach immune to both.

**Note on portability.** These were measured on macOS. On Linux a pipe's `st_size` is
conventionally 0 rather than a buffered-byte count. **The recommendation is unchanged and
the reasoning is strengthened, not weakened**: the value is 0 on one platform and arbitrary
on another, so no stat-based cap is portable. Any test asserting a *specific* `st_size` for
a pipe would be platform-dependent and must not be written; assert on the read cap instead.

## 4. Not verified

- gpg `read_passphrase_from_fd` (`g10/passphrase.c:149`) — R1's third data point. Not
  independently checked. It agrees with OpenSSL in R1's account, and the OD-2 decision holds
  on the geth-vs-OpenSSL disagreement alone, so nothing downstream depends on it.
- staking-deposit-cli's `_process_password` byte-equivalence to `normalize_passphrase`.
  Not checked; it supports the "S-B is unconstrained" claim, which *relaxes* a requirement
  rather than tightening one. If S-B is ever made a parity gate, verify it first.

**Downstream:** [`index.md`](index.md) · PRD FR-8, FR-9, FR-14, FR-16, FR-22, FR-23
