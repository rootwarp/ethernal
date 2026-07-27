# R2 — File-reading policy: prior art, measurements, and the no-new-dep recipe

**Question.** Evidence for **FR-13 – FR-19** and **FR-23**: is a 4 KiB ceiling sane, is following
symlinks right, what is the correct Rust technique for reading a secret without leaving heap
copies (**zero new dependencies**, PRD M-4), and do `/dev/fd/N` and process substitution behave as
the PRD assumes?

Everything in §1 – §4 marked **measured** was run on this host (Darwin 25.5.0, bash 3.2, zsh,
rustc from the repo toolchain) and is reproducible from the commands shown.

---

## 1. Size ceiling (FR-16)

### 1.1 What prior art bounds

| Tool | Bound | On exceeding it |
|---|---|---|
| **OpenSSL** `-pass file:` | `char tpass[APP_PASS_LEN]`, `#define APP_PASS_LEN 1024` (`apps/include/apps.h:360`), enforced by `BIO_gets(pwdbio, tpass, APP_PASS_LEN)` (`apps/lib/apps.c:295`) | **silently truncated** to 1023 bytes |
| **GnuPG** `--passphrase-file` | none — grows 100 bytes at a time from `xmalloc_secure` (`g10/passphrase.c:134-151`) | n/a |
| **go-ethereum** `--password` | none — `os.ReadFile(path)` (`cmd/geth/accountcmd.go:230`) | n/a; `geth account new --password /dev/zero` reads until memory is exhausted |
| **ethernal (proposed)** | 4 KiB | exit 2 |

**1 KiB is the only hard number anyone publishes, and OpenSSL's response to exceeding it is the
worst possible one for this repo**: a silently truncated scrypt password is a silently different
derived key — the exact failure class PRD §4.2 exists to eliminate.

**Verdict: 4 KiB is sane** — 4× OpenSSL's, ~500× any realistic passphrase, and small enough that
the buffer can simply be allocated unconditionally (§3.2). **Keep FR-16's exit 2; do not
truncate.** With FR-19b's 8-byte floor this gives a closed interval `[8, 4096]` for a keystore
passphrase, which is a one-line statement in the user guide.

### 1.2 Where length is not knowable — measured

```
$ python3 -c "import os,stat; ..."          # os.stat on each path
/dev/zero    size=0  ischar=True   isfifo=False  mode=666
/dev/stdin   size=0  ischar=True   isfifo=False  mode=444
fifo1        size=0  ischar=False  isfifo=True   mode=644     # mkfifo, no writer
/dev/fd/63   size=6  ischar=False  isfifo=True   mode=440     # from <(printf "secret")
```

Two facts that constrain the implementation:

1. **`/dev/zero` reports `len() == 0`.** A ceiling implemented as `if metadata.len() > CAP` never
   fires on it. FR-16's "skipped for FIFOs/character devices … bounded by a read cap instead" is
   therefore not an optimisation, it is the **only** thing that stops `--passphrase-file
   /dev/zero`. It must be a read cap, not a stat cap.
2. **A pipe's `len()` is the currently-buffered byte count, not a length** — `/dev/fd/63` reported
   6 for a 6-byte payload only because the writer had already flushed. It is a race, and
   pre-sizing a buffer from it would be a bug. **Never pre-size from `len()` unless
   `file_type().is_file()`.**

## 2. Symlinks (FR-15)

**Following is right, and the PRD's justification should be re-pointed.**

- **Kubernetes is the decisive case.** Every user-visible file in a projected Secret volume is a
  *symlink*: `<target-dir>/<key> -> ..data/<key>`, and `..data` is itself a symlink to a
  timestamped directory (`pkg/volume/util/atomic_writer.go:50-133`, quoted in the file's own
  header comment). An implementation that called `symlink_metadata` and demanded a regular file
  would **reject every Kubernetes-mounted secret**, and one that stat'd the link rather than the
  target would read the wrong mode.
- **Docker Swarm is the counter-shape**: `/run/secrets/<name>` is a plain regular file, listed as
  `-r--r--r--` (0444) in Docker's own example output.
- **`pass` does not fit the PRD's phrasing.** `~/.password-store` entries are `.gpg` files, not
  symlinks, and `pass show name` writes to **stdout** — the integration path is process
  substitution (§4), not a path. FR-15's rationale should cite Kubernetes and `/run/secrets`;
  drop `pass` from that sentence or move it to the process-substitution example.
- **Refinement — use the fd, not the path.** OpenSSH checks permissions with `fstat(fd, &st)` on
  the already-opened file (`authfile.c:82-87`), never `stat(path)`. Same semantics as
  `fs::metadata` for symlink following (both see the resolved target), plus it is TOCTOU-free:
  the mode checked, the type checked, and the bytes read are all the same inode. In Rust that is
  `let mut f = File::open(path)?; let md = f.metadata()?;` — `File::metadata` is `fstat` on the
  open descriptor. **Recommend this over `fs::metadata(path)` for FR-15/FR-17.**

## 3. Reading a secret without heap residue (FR-23)

### 3.1 The premise is confirmed by `zeroize`'s own source

`zeroize` 1.9.0 (the version in `Cargo.lock`), `src/lib.rs:520-538`:

```rust
impl<Z> Zeroize for Vec<Z> where Z: Zeroize {
    /// "Best effort" zeroization for `Vec`.
    ///
    /// Ensures the entire capacity of the `Vec` is zeroed. Cannot ensure that
    /// previous reallocations did not leave values on the heap.
    fn zeroize(&mut self) {
        self.iter_mut().zeroize();
        self.clear();
        self.spare_capacity_mut().zeroize();
    }
}
```

Two consequences, both load-bearing:

- **Spare capacity *is* covered.** So `truncate()` after a short read is safe — the bytes between
  the new length and the capacity are zeroed on drop. No manual scrub needed.
- **Reallocation is *not* covered**, and the crate says so in its own doc comment. This is exactly
  FR-23's rationale, confirmed from the primary source rather than assumed. A `Vec` that grows
  leaves the old allocation — containing the secret — on the heap, un-zeroed, for the allocator to
  hand to anyone.

Prior art solves the same problem with a wiping allocator: GnuPG's growth loop reallocates in
100-byte steps but from `xmalloc_secure`, freeing the previous buffer with `xfree`
(`g10/passphrase.c:138-145`). **We have no wiping allocator and cannot add one (M-4), so
"never reallocate" is our equivalent** — and it is strictly simpler.

### 3.2 The recipe — std only, one code path, no new deps

Everything needed is already in `std` or already in the tree: `std::fs::File`,
`std::io::Read`, `std::os::unix::fs::{FileTypeExt, PermissionsExt}` (the repo already uses
`PermissionsExt::mode()` at `gen_cmd.rs:424-427`), and `zeroize`.

```rust
const CAP: usize = 4096;                       // FR-16

let mut f = File::open(path)?;                 // follows symlinks (FR-15); `mut` for `Read::read`
let md = f.metadata()?;                        // fstat on the fd — no TOCTOU
if md.is_dir() { /* exit 2, FR-14 */ }
if md.file_type().is_file() && md.len() > CAP as u64 { /* exit 2, FR-16 — early, nice message */ }
#[cfg(unix)]
if md.file_type().is_file() && md.permissions().mode() & 0o077 != 0 { /* WARNING, FR-17 */ }

// One fixed buffer for every file type. Never grows, so never reallocates.
let mut buf = Zeroizing::new(vec![0u8; CAP + 1]);   // +1 byte is the overflow sentinel
let mut n = 0;
while n < buf.len() {
    match f.read(&mut buf[n..]) {
        Ok(0) => break,
        Ok(k) => n += k,
        Err(e) if e.kind() == ErrorKind::Interrupted => continue,
        Err(e) => return Err(/* FR-13 */),
    }
}
if n > CAP { /* exit 2, FR-16 — the read cap that /dev/zero needs */ }
buf.truncate(n);                               // spare capacity still zeroed on drop
```

Why this shape rather than the PRD's "allocate from the known length, then read":

- **One path for regular files, FIFOs and character devices.** The known-length variant needs a
  second branch for the two cases where the length is unknown or a lie (§1.2), and the branch is
  where the bug would live.
- **TOCTOU-proof by construction.** A file that grows between `metadata()` and the read cannot
  force a reallocation, because the buffer is not sized from the metadata. The `metadata().len()`
  check stays, but only as an early, better-worded rejection for regular files — never as the
  allocation size.
- `read_exact` is wrong here: a FIFO delivers short reads, and a regular file that shrank between
  fstat and read would fail with `UnexpectedEof` rather than the intended message.
- `f.take(CAP+1).read_to_end(&mut buf)` looks equivalent and would probably not reallocate given
  sufficient pre-reserved capacity, but that is an unspecified implementation detail of
  `read_to_end`'s probe/reserve strategy. The explicit loop costs ten lines and is a guarantee.
- 4097 zeroed bytes is free; there is no case for sizing the allocation dynamically.

### 3.3 The trait boundary reintroduces one copy — bound it

`PassphraseSource::read` returns a plain `Vec<u8>` and its own doc comment calls the re-wrap a
"secret-residue footgun" (`passphrase.rs:26-34`). `FileSource` must therefore hand back a
non-zeroizing `Vec`. Build it as `Vec::with_capacity(n)` + `extend_from_slice(&buf[..n])` so that
copy also never reallocates, and let the internal `Zeroizing` buffer drop immediately after.
Callers already re-wrap: `MinLenPassphrase::read` does `Zeroizing::new(self.inner.read()?)`
(`keygen.rs:224`), and `KeyLoader::load` does the same — so FR-19b's decorator wrapping
(`validator_cmd.rs:98`/`:159`, `account_cmd.rs:103`/`:159`) is also what keeps the returned `Vec`
scrubbed. **Wrapping `FileSource` in `MinLenPassphrase` is a hygiene requirement as well as a
length requirement.**

### 3.4 Correction to FR-23's cited precedent

FR-23 says the pre-sized technique is "the same S-1 discipline `RecoverMnemonicSource` already
applies to piped stdin". Measured against the code, that is not what the existing path does —
`keygen.rs:350-353`:

```rust
let mut buf = Zeroizing::new(String::new());
io::stdin().read_to_string(&mut buf)?;
```

`Zeroizing` from the first allocation, yes; **pre-sized, no** — `read_to_string` grows and
reallocates, so a mnemonic longer than the first probe leaves un-zeroed copies behind, precisely
the defect FR-23 is written to avoid. FR-23's technique is *stricter* than its cited precedent.

Two consequences: the citation in FR-23 should be corrected to avoid implying the pattern already
exists, and the existing stdin path carries the same residue property. Fixing `keygen.rs` is
**out of scope** for this change — recorded here so it is a deliberate omission rather than an
oversight, and so a reviewer does not "discover" it as a regression introduced by this work.

## 4. Process substitution and `/dev/fd/N` — measured (FR-6, FR-14, FR-22, FR-33)

Harness (`readtwice.sh`): stat the path, read it fully, then read it fully a second time.

| Invocation | Path handed to the flag | Type | `st_size` | mode | read 1 | read 2 |
|---|---|---|---|---|---|---|
| `bash -c './readtwice.sh <(printf secret)'` | `/dev/fd/63` | FIFO | 6 | 0440 | `b'secret'` | **`b''`** |
| `zsh -c './readtwice.sh <(printf secret)'` | `/dev/fd/11` | FIFO | 6 | 0440 | `b'secret'` | **`b''`** |
| `zsh -c './readtwice.sh =(printf secret)'` | `/tmp/zshIWwIfc` | regular | 6 | 0600 | `b'secret'` | `b'secret'` |
| `mkfifo fifo1` + one writer | `fifo1` | FIFO | 0 | 0644 | `secret` | **blocks indefinitely** |

Five findings.

1. **FR-22's read-twice defect is real and fatal.** The second read of a `<(...)` path returns
   **zero bytes**, so `tx run --signer local --rpc-url …` would derive `from` correctly and then
   fail (or, worse, attempt to construct a signer from an empty key) at signing time. The PRD is
   right that this is invisible without `--rpc-url`.
2. **A named FIFO is worse than EOF — it hangs.** With no second writer the second open blocks
   forever. So the read-once fix must be a *fix*, not a retry-with-better-error: there is no error
   to report, only a hung ceremony.
3. **FR-17's "regular file" scoping is load-bearing.** The process-substitution pipe is mode
   **0440** — `mode & 0o077 == 0o040 != 0`. Were the permission check not restricted to regular
   files, the *recommended* no-disk-file pattern would emit a WARNING on every single run, and
   would collide with FR-21's exactly-one-`WARNING` assertions. Keep the wording.
4. **`=(...)` is not `<(...)`.** zsh's `=(...)` materialises a temp file (regular, 0600, readable
   any number of times); bash has no equivalent. Worth one line in the user guide — it is the
   escape hatch for anyone who hits a read-twice path we have not fixed.
5. **The path is only alive for the duration of the command.** Measured: `f=<(printf secret)`
   followed by a later `cat "$f"` gives `Bad file descriptor` — the fd is closed once the
   assignment completes. Every user-guide example must pass `<(...)` **inline** as the flag
   argument; `F=<(...)` then `--passphrase-file "$F"` silently does not work.

## 5. `File::open` on a directory — measured (FR-14)

```
open(/tmp) = Ok; metadata.is_dir=true
read = Err((IsADirectory, "Is a directory (os error 21)"))
```

`File::open` **succeeds** on a directory; the failure only appears at the first `read`, as a raw
OS error. An explicit `md.is_dir()` check on the opened fd's metadata is required to produce
FR-14's intended message; without it the operator gets `Is a directory (os error 21)` from a code
path that looks like a read failure.

## 6. Recommendations

| # | Requirement | Verdict |
|---|---|---|
| FR-13 | not found / unreadable → exit 2 | **Keep.** No prior art disagrees; geth `Fatalf`s, OpenSSL returns NULL and prints `Can't open file %s`. |
| FR-14 | directory exit 2, FIFO/char accepted | **Keep**, with the explicit `is_dir()` check of §5 — `File::open` does not reject a directory. |
| FR-15 | follow symlinks | **Keep**, re-justified on Kubernetes (§2), and implemented as `File::open` + `File::metadata` (fstat), per OpenSSH. |
| FR-16 | 4 KiB ceiling, exit 2 | **Keep.** 4× OpenSSL's 1 KiB; must be a **read cap**, not a stat cap, because `/dev/zero` reports length 0 (§1.2). Never truncate. |
| FR-17 | mode warning, regular files only | **Keep the "regular file" scoping** — §4 finding 3 shows it is not cosmetic. Wording in [`r3`](r3-permission-warning.md). |
| FR-22 | read exactly once | **Keep, P0.** Measured EOF on the second read, and an indefinite block for a named FIFO. |
| FR-23 | no heap residue | **Keep the requirement, change the recipe** to the fixed 4097-byte buffer of §3.2 rather than "allocate from the known length" — one path, TOCTOU-proof, and the length is a lie for exactly the file types FR-14 promises to support. Correct the `RecoverMnemonicSource` citation (§3.4). |
| M-4 | zero new deps | **Satisfied.** `std::fs`, `std::io::Read`, `std::os::unix::fs::{FileTypeExt, PermissionsExt}`, `zeroize` (already in `Cargo.lock` at 1.9.0). Nothing else is needed. |

## 7. Sources

| Source | Reference |
|---|---|
| `zeroize` 1.9.0 | `~/.cargo/registry/src/index.crates.io-*/zeroize-1.9.0/src/lib.rs:520-538` · <https://docs.rs/zeroize/1.9.0/zeroize/trait.Zeroize.html> |
| OpenSSL (master) | [`apps/lib/apps.c#L219-L307`](https://github.com/openssl/openssl/blob/971b8d060e52499d6ffd2f9ca697fe23f72a629a/apps/lib/apps.c#L219-L307) · [`apps/include/apps.h#L360`](https://github.com/openssl/openssl/blob/971b8d060e52499d6ffd2f9ca697fe23f72a629a/apps/include/apps.h#L360) |
| GnuPG (master) | [`g10/passphrase.c#L114-L152`](https://github.com/gpg/gnupg/blob/3a8c7edec6c8da093e08bc6cbf63e36507da7149/g10/passphrase.c#L114-L152) |
| go-ethereum (master) | [`cmd/geth/accountcmd.go#L226-L240`](https://github.com/ethereum/go-ethereum/blob/ca1f2e4d38f4e94676981bb9251239a5d490b004/cmd/geth/accountcmd.go#L226-L240) |
| OpenSSH (master) | [`authfile.c#L82-L107`](https://github.com/openssh/openssh-portable/blob/7e446d3f5917c2f2770981a89d0e54d5d064bf0c/authfile.c#L82-L107) |
| Kubernetes (master) | [`pkg/volume/util/atomic_writer.go#L50-L133`](https://github.com/kubernetes/kubernetes/blob/0f317be40dfb054367e4f126845c91ffdd22cdb8/pkg/volume/util/atomic_writer.go#L50-L133) |
| Docker Swarm secrets | <https://docs.docker.com/engine/swarm/secrets/> |

**Connections:** [`r1-secret-file-line-endings.md`](r1-secret-file-line-endings.md) ·
[`r3-permission-warning.md`](r3-permission-warning.md) · [`index.md`](index.md)
