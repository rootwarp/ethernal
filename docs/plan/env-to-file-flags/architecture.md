# Architecture — env-var-name flags → file-path flags

**Binding for the issue breakdown.** Where this document and the PRD disagree, this document
wins and the divergence is recorded in §11.

Inputs: [`prd.md`](prd.md) (FR-1…FR-38, S-A…S-D, OD-1…OD-7) ·
[`research/index.md`](research/index.md) (R1–R3) ·
[`research/r4-verification-log.md`](research/r4-verification-log.md) (what is verified) ·
[`research/r2-file-reading-policy.md`](research/r2-file-reading-policy.md) (the read recipe).

Claims listed as **unverified** in R4 §4 — gpg's `read_passphrase_from_fd`, and
staking-deposit-cli's `_process_password` byte-equivalence — are not relied on anywhere below.

---

## 1. Shape of the change

One new workspace crate, two edited crates, seven edited bin modules. Zero new third-party
dependencies (M-4). No new threads, no change to any keystore byte on disk.

```
crates/ethernal-secretfile/        NEW   the read primitive + the two byte rules (§2)
crates/ethernal-keystore/
  src/passphrase.rs                EDIT  + FileSource (beside EnvSource, retained)
  src/error.rs                     EDIT  + PassphraseFile / PassphraseFileEmpty; NoTty text
  src/lib.rs                       EDIT  re-export FileSource
crates/ethernal-signer/
  src/local.rs                     EDIT  + new_local_signer_from_file; FR-28 doc rewrite
  src/errors.rs                    EDIT  + SignerError::KeyFile
  src/lib.rs                       EDIT  re-export
bins/ethernal/src/
  fs_util.rs                       EDIT  + secret_file_arg (the `-` guard, FR-6)
  keystore_cli.rs                  EDIT  flag defs; MnemonicPassphraseForm::File; parse + warn sink
  validator_cli.rs                 EDIT  passphrase_file; usage strings
  account_cli.rs                   EDIT  ditto
  gen_cli.rs                       EDIT  ditto
  validator_cmd.rs                 EDIT  FileSource in place of EnvSource (2 sites)
  account_cmd.rs                   EDIT  ditto (2 sites)
  gen_cmd.rs                       EDIT  read-once before the worker pool (D-5)
  sign_cmd.rs                      EDIT  SignConfig.private_key_file; one construction site
  run_cmd.rs                       EDIT  single LocalSigner, passed forward (D-4)
  errors.rs                        EDIT  explicit exit-code arms + assertions
docs/USER-GUIDE.md · README.md · CHANGELOG.md · .claude/skills/verify/SKILL.md
```

`ethernal-core` and `ethernal-tx` are **untouched**.

## 2. The read primitive: a new leaf crate

### 2.1 Why a crate and not a module (D-1)

Two crates need byte-identical file discipline: `ethernal-keystore` for the three passphrase
files and `ethernal-signer` for the hex private key. FR-10 and FR-27 require one rule, and
"one rule" enforced by convention across two crates is a rule that drifts.

Rejected, with reasons:

- **`ethernal-signer` depends on `ethernal-keystore`.** Rejected. It inverts the layering — a
  keystore is a consumer of key material, not a supplier of file plumbing — and it drags
  `scrypt`, `aes`, `ctr`, `unicode-normalization`, `serde_json` and, worst, **`rpassword`**
  into a signing crate. A signer that cannot be linked without a terminal-password library is
  not a signer anyone can embed.
- **Lift into `ethernal-core`.** Rejected. `ethernal-signer` already reaches core transitively
  (`signer → tx → core`), so that edge is free — but `ethernal-keystore` does **not** depend on
  core today, and adding the edge pulls `blst` (a C library) into the build of the audited,
  currently pure-Rust keystore crate. `ethernal-core` is also the *deposit pipeline* crate;
  `output::write_new_0600` lives there because it writes deposit data, not because core is the
  repo's filesystem home.
- **Duplicate ~80 lines in each crate.** Rejected. The duplicate is not only the read loop but
  the error enum, the permission-mask constant, the warning wording (which FR-21 keys tests
  on), and the tests. Drift here is silent and lands in a derived key.

Cost of the new crate is one `Cargo.toml`. `Cargo.toml`'s `members = ["bins/*", "crates/*"]`
globs; `make lint`/`make test`/`make e2e-mock` are all `--workspace`; CI invokes only those
targets plus `cargo build --release --features ledger`. **Nothing in the repo enumerates the
crates**, so no plumbing changes. The duplicate-plus-conformance-test fallback is carried in
the risk table (R-1) in case the project plan wants to avoid a fifth crate.

### 2.2 Public surface

`crates/ethernal-secretfile` — dependencies `zeroize`, `thiserror` (both already
`[workspace.dependencies]`; M-4 holds).

```rust
/// FR-16. The read buffer is one byte larger; the extra byte is the overflow sentinel.
pub const MAX_SECRET_FILE_BYTES: usize = 4096;

/// What FR-9 found after FR-8 stripped one trailing `\n`. A shape or a count,
/// never content (M-3).
#[derive(Debug, Clone, Copy)]
pub enum Residual {
    /// A `\r` anywhere: `pw\r`, `pw\r\n`, `pw\r\r\n`.
    CarriageReturn,
    /// Two or more lines.
    MultiLine { lines: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum SecretFileError {
    NotFound { path: String },
    PermissionDenied { path: String },
    IsDirectory { path: String },
    TooLarge { path: String, max: usize },
    NotUtf8 { path: String },
    LineTerminator { path: String, found: Residual },
    Io { path: String, source: std::io::Error },
}

/// Reads a one-line secret under the full file policy (FR-13…FR-17, FR-23) and
/// applies the **passphrase** byte rule: strip exactly one trailing `\n` (FR-8),
/// then reject any residual `\r` or `\n` (FR-9). Validates UTF-8 (FR-12b, D-3).
///
/// An empty file yields an empty string. Whether empty is an error is the
/// caller's policy (FR-18) and is deliberately not decided here.
pub fn read_secret_line(path: &Path, warn_out: &mut dyn Write)
    -> Result<Zeroizing<String>, SecretFileError>;

/// Same file policy, but the **hex-key** byte rule (FR-7): all leading and
/// trailing ASCII whitespace trimmed. A separate entry point rather than a flag,
/// so the divergence from `read_secret_line` is visible at every call site and
/// cannot be selected by accident.
pub fn read_secret_trimmed(path: &Path, warn_out: &mut dyn Write)
    -> Result<Zeroizing<String>, SecretFileError>;
```

Four public items. Nothing else is exported — in particular the raw byte reader stays private,
so no consumer can bypass a byte rule.

### 2.3 The read loop

Both entry points share one private body. This is R2 §3.2's recipe, with the failure branches
made explicit:

```rust
fn read_capped(path: &Path, warn_out: &mut dyn Write)
    -> Result<Zeroizing<Vec<u8>>, SecretFileError>
{
    // Follows symlinks (FR-15) — every file in a Kubernetes projected Secret
    // volume is one. NotFound / PermissionDenied are classified from the open
    // error; everything else is Io.
    let mut f = File::open(path).map_err(|e| classify_open(path, e))?;

    // fstat on the open descriptor, following OpenSSH authfile.c:82-87: the mode
    // checked, the type checked and the bytes read are the same inode (FR-15).
    let md = f.metadata().map_err(|e| SecretFileError::Io { .. })?;

    // FR-14. Measured: File::open("/tmp") SUCCEEDS; without this the failure
    // surfaces at the first read as "Is a directory (os error 21)" from a code
    // path that looks like a read failure (R4 M-b).
    if md.is_dir() { return Err(SecretFileError::IsDirectory { .. }); }

    let ft = md.file_type();
    // Early, better-worded rejection for regular files ONLY. Never the
    // enforcement, never an allocation size: /dev/zero reports len()==0 (R4 M-a)
    // and a pipe reports an arbitrary snapshot of buffered bytes — 0 on Linux,
    // measured 9 for a 9-byte payload on macOS (R4 §3).
    if ft.is_file() && md.len() > MAX_SECRET_FILE_BYTES as u64 {
        return Err(SecretFileError::TooLarge { .. });
    }

    // FR-17. "Regular file" is load-bearing, not cosmetic: a <(...) pipe is mode
    // 0440 (R4 M-e), so without it the recommended no-disk-file pattern would
    // warn on every run and collide with FR-21.
    #[cfg(unix)]
    if ft.is_file() && md.permissions().mode() & 0o077 != 0 {
        let _ = writeln!(warn_out,
            "WARNING: file permissions {:04o} for {:?} are too open; \
             the secret is readable by group or other. Fix with: chmod 600 {:?}",
            md.permissions().mode() & 0o7777, path, path);
    }

    // ONE allocation, never grown, never reallocated (FR-23). zeroize 1.9.0's own
    // doc comment: "Ensures the entire capacity of the Vec is zeroed. Cannot
    // ensure that previous reallocations did not leave values on the heap."
    let mut buf = Zeroizing::new(vec![0u8; MAX_SECRET_FILE_BYTES + 1]);
    let mut n = 0usize;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(SecretFileError::Io { .. }),   // buf drops zeroized
        }
    }
    // The read cap. This — not the stat check — is what stops /dev/zero.
    if n > MAX_SECRET_FILE_BYTES { return Err(SecretFileError::TooLarge { .. }); }

    buf.truncate(n);   // safe: zeroize covers spare capacity (R2 §3.1)
    Ok(buf)
}
```

`read_exact` is wrong here (a FIFO delivers short reads); `take(..).read_to_end(..)` relies on
an unspecified reserve strategy. The explicit loop is ten lines and is a guarantee.

**UTF-8 without residue.** Both entry points then do:

```rust
std::str::from_utf8(&buf).map_err(|_| SecretFileError::NotUtf8 { .. })?;  // borrow, no move
let owned = std::mem::take(&mut *buf);                                     // move the allocation
Zeroizing::new(String::from_utf8(owned).expect("validated on the line above"))
```

The borrow-check first is not redundant: `String::from_utf8` returns `Err(FromUtf8Error)` which
**owns the plain `Vec<u8>`** and drops it un-zeroized. Validating before moving means the move
only happens on the success path. Cost is one extra scan of ≤4096 bytes. `Zeroizing<String>`
zeroes through `String::as_mut_vec`, so the 4096 bytes of retained spare capacity are still
scrubbed on drop.

**The byte rules**, applied to the validated string:

```rust
// read_secret_line — FR-8 then FR-9.
let s = s.strip_suffix('\n').unwrap_or(&s);          // exactly one, and nothing else
if s.contains('\r') { return Err(LineTerminator { found: Residual::CarriageReturn }); }
if s.contains('\n') { return Err(LineTerminator { found: Residual::MultiLine {
    lines: s.matches('\n').count() + 1 } }); }

// read_secret_trimmed — FR-7.
let s = s.trim_matches(|c: char| c.is_ascii_whitespace());
```

A trailing **space or tab is kept** by `read_secret_line`. That is the rule, it is the reason
FR-11 requires the guide to say so in bytes, and it is what makes "strip what all three surveyed
tools call a terminator, keep what they all call content, refuse what they disagree about"
consistent rather than arbitrary.

Both rules re-slice in place; no intermediate allocation, so no second copy to scrub.

## 3. The UTF-8 boundary (D-3)

**`FileSource` validates UTF-8 at the boundary. All three passphrase consumers fail closed.**

The decisive argument is that **no capability is lost relative to the flag being replaced**.
`std::env::var` returns `Err` on non-UTF-8, which `EnvSource` folds into `EnvVarEmpty`
(`passphrase.rs:54-64`) — an operator could never have supplied those bytes through
`--passphrase-env` either. Refusing them through the file is not a regression; it is the same
answer with a better message.

Consequence per consumer, stated explicitly as the PRD requires:

| # | Consumer | Today, if a file carried an invalid byte | After |
|---|---|---|---|
| **S-B** | v4 keystore (`validator`, `deposit gen`) | `normalize_passphrase` lossy-decodes it to U+FFFD and **silently changes the derived key** — `crypto.rs:38-44`, whose own comment says "which would change the derived key" | exit 2 naming the path, before any keystore is written |
| **S-C** | v3 keystore (`account`) | raw bytes, round-trips correctly | exit 2. The only case where validation removes something that would have worked — see below |
| **S-D** | mnemonic passphrase | hard error `Bip39Error::PassphraseNotUtf8` (`bip39.rs:187`) | exit 2, raised earlier, message names the path |

S-B is the case the decision exists for: it is the silent one, and it changes a 32-ETH key.

S-C is the cost. Two things make it acceptable. First, the capability argument above — the env
flag could not deliver those bytes. Second, **refusing is the reversible direction**, exactly as
in OD-2: accepting raw bytes later cannot invalidate a key created under the strict rule, because
no key could be created under it. Note this is a divergence from geth, whose Go strings are byte
strings and whose `--password` would accept such a file; it belongs in the user guide's
"deliberately unlike prior art" list beside the CRLF row, and it is the same family of reasoning.

Fixing the three-way divergence itself stays out of scope (PRD FR-12b).

**Downstream gate consequence.** OD-7 already requires the H9 and A5-M manual parity sessions to
gain a bare-CR case and a CRLF case; a **non-UTF-8 case** belongs alongside them, asserting exit
2. A5-M's `geth account import --password <file>` round-trip must use a UTF-8 file, or it tests
the wrong thing.

## 4. `FileSource` — the keystore boundary

`crates/ethernal-keystore/src/passphrase.rs`, immediately after `EnvSource`, which is
**retained** (M-5, A-2):

```rust
/// A [`PassphraseSource`] that reads the passphrase from a file.
///
/// The whole secret-file policy comes from
/// [`ethernal_secretfile::read_secret_line`]: symlinks followed, directories
/// rejected, 4 KiB read cap, one trailing `\n` stripped and any residual `\r`
/// or `\n` refused, UTF-8 validated. At most **one** loose-permission WARNING
/// is emitted per source, however many times `read` is called (FR-17, FR-21).
///
/// An empty file is [`KeystoreError::PassphraseFileEmpty`], mirroring
/// [`KeystoreError::EnvVarEmpty`] for the source this replaces (FR-18).
pub struct FileSource {
    path: PathBuf,
    warn_out: Mutex<Box<dyn Write + Send>>,
    warned: AtomicBool,
}

impl FileSource {
    /// `warn_out` is typically `std::io::stderr()`; pass `std::io::sink()` for none.
    pub fn new<W: Write + Send + 'static>(path: impl Into<PathBuf>, warn_out: W) -> Self;
    /// The path, for messages. Never the contents.
    pub fn path(&self) -> &Path;
}

impl PassphraseSource for FileSource { fn read(&self) -> Result<Vec<u8>, KeystoreError>; }
```

Four notes on the shape.

- **The writer is injected, not `stderr()` internally.** This is `TermPromptSource`'s existing
  pattern (`passphrase.rs:72-79`) and it is what lets FR-21's warning-counting tests be
  deterministic. A library that writes to stderr behind the caller's back is worse.
- **`Sync`.** `Mutex<Box<dyn Write + Send>>` + `AtomicBool` + `PathBuf` is `Sync`, which
  `deposit gen`'s `&(dyn PassphraseSource + Sync)` bound (`gen_cmd.rs:143`) requires.
- **The warning latch.** `warned.swap(true)` selects `io::sink()` for every read after the
  first. Combined with §6's ordering table this makes "exactly one WARNING" a property of the
  type rather than a coincidence of call order.
- **FR-23b.** `read` builds its return as `Vec::with_capacity(s.len())` + `extend_from_slice`
  and drops the `Zeroizing<String>` immediately, so the mandatory boundary copy also never
  reallocates.

### 4.1 `MinLenPassphrase` composes unchanged (FR-19b)

The 8-byte floor is applied by a decorator at the call site, not inside the source. Today
(`validator_cmd.rs:94-103`, `:155-164`; `account_cmd.rs:98-108`, `:154-164`):

```rust
let keystore_pw: &dyn PassphraseSource = if !cfg.passphrase_env.is_empty() {
    env_source = EnvSource::new(&cfg.passphrase_env);
    checked = MinLenPassphrase { inner: &env_source, min: KEYSTORE_PASSPHRASE_MIN_LEN };
    &checked
} else { tty_pw = NewKeystorePassphrase::new(std::io::stderr()); &tty_pw };
```

After — same block, one constructor swapped, at all four sites:

```rust
let keystore_pw: &dyn PassphraseSource = if let Some(p) = &cfg.passphrase_file {
    file_source = FileSource::new(p.clone(), std::io::stderr());
    checked = MinLenPassphrase { inner: &file_source, min: KEYSTORE_PASSPHRASE_MIN_LEN };
    &checked
} else { tty_pw = NewKeystorePassphrase::new(std::io::stderr()); &tty_pw };
```

Length is measured **after** FR-8 stripping for free: `FileSource::read` returns post-strip
bytes and `require_min_len` normalizes those (`passphrase.rs:173`). Worked example, which is the
PRD's acceptance bullet: `"1234567\n"` is 8 raw bytes → FR-8 → 7 → EIP-2335 normalize → 7 →
`PassphraseTooShort { min: 8, got: 7 }` → exit 2.

Wrapping is also a hygiene requirement, not only a length one: `MinLenPassphrase::read`
re-wraps the plain `Vec` in `Zeroizing` (`keygen.rs:224`), which is what scrubs the boundary
copy of §4's last bullet.

## 5. The signer boundary

`crates/ethernal-signer/src/local.rs`, beside `new_local_signer_from_env` (retained):

```rust
/// Reads a hex-encoded private key from `path` and constructs a [`LocalSigner`].
///
/// Same file policy as the keystore passphrase — one implementation, in
/// `ethernal-secretfile` — with the **hex** byte rule (FR-7): all leading and
/// trailing ASCII whitespace is trimmed before parsing. Only the PATH ever
/// appears in an error; the contents never do.
///
/// `warn_out` receives at most one loose-permission WARNING (FR-17); pass
/// `std::io::sink()` for none.
pub fn new_local_signer_from_file(
    path: &Path,
    warn_out: &mut dyn Write,
) -> Result<LocalSigner, SignerError>;
```

Body: `read_secret_trimmed(path, warn_out).map_err(SignerError::KeyFile)?` then
`new_local_signer_from_hex(&s)`, with the existing `map_err` that replaces the inner error with
a path-only context so no key material can leak.

**No empty-file rule is needed here.** An empty file is not a distinct case: it fails
`new_local_signer_from_hex`'s `stripped.len() != 64` check with "expected 32-byte (64 hex char)
private key" — S-A's *loud* property, and the correct message. FR-18 scopes the empty rule to
the two passphrase flags, which is right, because those are the only ones where an empty secret
is otherwise indistinguishable from a valid one.

**FR-28 doc rewrite.** `local.rs:70-73` ("The key MUST come from a secure source (environment
variable…). It MUST NEVER appear in argv") and `local.rs:85` ("Prefer `new_local_signer_from_env`
in CLI code so the key never appears in argv") are rewritten: the *key* still must never appear
in argv; the *path* does, and the guarantee that buys is that a child process inherits a path,
not a secret. `new_local_signer_from_file` becomes the recommendation for CLI code.

**On PRD §2.1.** `run_deposit_cli_verify` (`gen_cmd.rs:400-419`) spawns
`deposit verify --input-file <path>` and passes **no** passphrase — the leak was purely
environment inheritance. After this change there is no secret in the environment to inherit, so
the defect closes without touching that call site. `.env_clear()` is not the fix and would in
fact break the bare-name PATH resolution `look_path` relies on. Out of scope, recorded so it is
not re-raised.

## 6. Read-once, and where each file is read

### 6.1 `tx run` / `tx sign` — the sharp case (D-4)

Today `run_action` constructs a `LocalSigner` to derive `from` (`run_cmd.rs:165`), closes it,
then hands `private_key_env_var` into `SignConfig` (`:193`) and `sign_unsigned_tx` constructs a
**second** signer (`sign_cmd.rs:174`). The comment at `run_cmd.rs:162` already admits the key
"is read here and again". Measured (R4 M-c, M-d): a second read of a `<(...)` path returns
**zero bytes**; a second open of a named FIFO **blocks indefinitely** — no error, only a hung
ceremony. This cannot be softened into a better message.

**The fix passes the constructed signer forward, not the material and not the path.**

```rust
// sign_cmd.rs — the ONLY LocalSigner construction site in the binary.
/// Reads `--private-key-file` exactly once (FR-22) and constructs the signer.
/// Applies FR-19's hex-shaped-argument guard on the not-found branch.
pub(crate) fn local_signer_from_file(
    path: &Path,
    warn_out: &mut dyn Write,
) -> Result<LocalSigner, AppError>;

pub fn sign_unsigned_tx(
    cfg: &SignConfig,
    local: Option<&LocalSigner>,      // Some ⟺ cfg.signer == "local"
    err_writer: &mut dyn Write,
    unsigned: &UnsignedTx,
    cancel: &CancelToken,
) -> Result<SignedTx, AppError>;
```

- `("local", Some(s))` → sign with `s`, and **do not close it**. `sign_unsigned_tx` closes only
  the signer it constructed itself. Closing a borrowed signer would zeroize a key the owner
  still holds and make a later `address()` return `SignerClosed`. The owner calls
  `let _ = s.close();` immediately after `sign_unsigned_tx` returns, preserving today's
  prompt-zeroize timing; `LocalSigner: Drop` (`local.rs:240`) is the backstop.
- `("ledger", _)` → unchanged: construct, sign, `close()`.
- `("local", None)` → `AppError::Internal`; unreachable, gated by `load_*_config` (FR-24).

**`SignConfig.private_key_env_var: String` becomes `pub private_key_file: Option<PathBuf>`** —
the **path**, not the material. `RunConfig` the same. The material never enters either struct.
This is not stylistic: `Zeroizing<Z>` **derives `Debug`** (zeroize 1.9.0 `src/lib.rs:602`), so a
`Zeroizing<String>` field would print in full under the structs' existing `#[derive(Debug)]` —
the compiler would not stop it. Keeping material out of the config is the only version of this
that needs no hand-written `Debug` and cannot regress. `Option` rather than `PathBuf` because
`--signer ledger` legitimately has none; FR-24's "required for `--signer local`" is enforced in
`load_sign_config`/`load_run_config`, not by the type.

One consequence to make load-bearing rather than incidental: after this change **nothing inside
`sign_unsigned_tx` reads `private_key_file`**. `run_action`'s synthetic `SignConfig`
(`run_cmd.rs:189-194`, which today copies `private_key_env_var` across) therefore sets
`private_key_file: None`. A live path left in that struct is dead data that invites exactly the
second open D-4 exists to prevent; its **absence**, not a comment, is what structurally forbids
one.

**`run_action` step order**, chosen to preserve today's error precedence:

```
0.  require_ledger_flags_for_rpc(cfg)                       unchanged (config gate)
1.  read_input(--input-file)                                unchanged — still first
1b. if signer == "local" { local = Some(local_signer_from_file(..)?) }   ← now for ALL local runs
1c. if local.is_some() && !rpc_url.is_empty() { cfg.build.from = local.address()? }
2.  build_unsigned_tx                                       unchanged
3.  optional --keep-unsigned write                          unchanged
4.  sign_unsigned_tx(&sign_cfg, local.as_ref(), ..)         no second construction
5.  let _ = local.close()                                   prompt zeroize
```

Two existing tests pin this and must stay green unmodified: `run::invalid_input` (bad JSON,
**good** key → exit 2 — step 1 still precedes 1b) and `run::bad_key` (bad hex, good fixture →
exit **3** — a malformed key is `SignerError::InvalidKey`, not a file-policy failure, so it
keeps its code even though it now surfaces at 1b instead of step 4). For `tx sign` the
construction stays immediately before `sign_unsigned_tx`, so `sign::invalid_input_json` (exit 2)
is unaffected.

### 6.2 `deposit gen` — a second read-once site the PRD only gestures at (D-5)

`gen_cmd.rs:321` calls `loader.load(&keystore_path, pw_src)` **once per pubkey**, from up to
`--parallel` worker threads, and `KeyLoader::load` calls `pw.read()` (`keystore.rs:205`). With
`--passphrase-env` the N reads are free. With `--passphrase-file` they are N opens of the same
path, concurrently: for `<(...)` every read after the first returns zero bytes and surfaces as a
*wrong passphrase* (exit 3) on an arbitrary pubkey; for a named FIFO the run hangs.

Fix — read once, before the pool, and hand the workers an in-process source:

```rust
let file_pw; let tty_source;
let pw_src: &(dyn PassphraseSource + Sync) = if let Some(p) = &cfg.passphrase_file {
    // The single read (FR-22). InMemoryPassphrase is the established
    // in-process source (keystore_cli.rs:170, C4's D-6) and is Sync.
    let src = FileSource::new(p.clone(), std::io::stderr());
    file_pw = InMemoryPassphrase::new(src.read().map_err(AppError::Keystore)?);
    &file_pw
} else {
    tty_source = TermPromptSource::new(std::io::stderr());
    &tty_source
};
```

Side effect, deliberate and an improvement: a bad passphrase file now fails **before** any
worker starts, instead of mid-pool on an arbitrary pubkey.

The `TermPromptSource` branch keeps today's behavior (one prompt per pubkey). That is a
pre-existing UX wart; hoisting it too would change interactive behavior beyond this change's
scope. Recorded so a reviewer does not read it as an oversight.

### 6.3 Ordering invariant — read each file where its env counterpart is read today

**I-1.** Each secret file is read at exactly the point the corresponding `std::env::var` fires
today. Fail-fast hoisting to config-load time is **out of scope and actively harmful**: on
`validator new`/`account new`, `clear_after_ceremony` writes `CLEAR_SCROLLBACK_TWICE`
(`keygen.rs:86`) and erases everything printed before it, so a permission WARNING moved earlier
would be silently wiped and FR-17 would stop working with no test noticing. Keeping the read
where it is also means an unreadable file wastes the ceremony exactly as an unset env var does
today — no behavior change at all, which is why this is the no-change answer rather than a
compromise.

| Flag | Command | Read at | Post-ceremony? |
|---|---|---|---|
| `--passphrase-file` | `validator`/`account` `new`+`recover` | `finish_from_mnemonic` (`validator_cmd.rs:485`, `account_cmd.rs:323`) | **yes** — WARNING survives |
| `--passphrase-file` | `deposit gen` | once, before the worker pool (`gen_cmd.rs:143`) | n/a — no ceremony |
| `--mnemonic-passphrase-file` | `validator`/`account` `new`+`recover` | `parse_mnemonic_passphrase_form` at config load (`keystore_cli.rs:130`) | **no** — see below |
| `--private-key-file` | `tx sign` | `sign_cmd::run`, after input read + JSON parse | n/a |
| `--private-key-file` | `tx run` | `run_action` step 1b | n/a |

**I-2 (accepted limitation).** The `--mnemonic-passphrase-file` permission WARNING is emitted at
config load, before `run_ceremony`, and is therefore erased on `validator new` / `account new`.
This is the **same pre-existing property** as the symlinked-output-dir WARNING, which is emitted
from `validator_cli.rs:192` / `account_cli.rs:181` at config load and is likewise erased — which
is why the e2e test that asserts it runs on `recover` (`validator_e2e.rs:514`), not `new`. It is
durable on `recover`, `gen` and `tx`. Fixing the ceremony's erasure of earlier warnings is a
separate change; recorded here so it is not mistaken for a regression introduced by this work.

## 7. Error taxonomy and exit codes

`SecretFileError` is the single vocabulary; it is mapped at **three** sites, each of which needs
its own explicit assertion because `errors.rs`'s `_ => 2` (keystore) and `_ => 1` (signer)
catch-alls would otherwise absorb the new variants silently. The pattern to follow is the
`EnvVarEmpty` assertion at `errors.rs:534`.

| Site | Type | Mapping | Exit |
|---|---|---|---|
| `FileSource::read` | `KeystoreError::PassphraseFile(SecretFileError)` | falls into the existing `_ => 2` arm (`errors.rs:292`) | 2 |
| `FileSource::read`, empty file | `KeystoreError::PassphraseFileEmpty { path }` | same arm | 2 |
| `new_local_signer_from_file` | `SignerError::KeyFile(SecretFileError)` | **new explicit arm** in the signer block | 2 |
| `parse_mnemonic_passphrase_form` | `AppError::exit2(format!("--mnemonic-passphrase-file: {e}"))` | `AppError::Exit { code }` | 2 |

Two new `KeystoreError` variants, not seven (D-6):

```rust
/// The passphrase file could not be read, or violates the file policy:
/// not found, permission denied, a directory, over-size, a residual `\r`
/// or `\n`, or not UTF-8. Never carries file contents. Exit code 2.
#[error("passphrase file: {0}")]
PassphraseFile(#[from] SecretFileError),

/// `--passphrase-file` named an empty file (0 bytes, or a lone newline).
/// Mirrors [`KeystoreError::EnvVarEmpty`], the source it replaces. Exit 2.
#[error("passphrase file is empty: {path}")]
PassphraseFileEmpty { path: String },
```

Wrapping the typed source rather than flattening to a string keeps every failure *mode*
matchable — `matches!(e, KeystoreError::PassphraseFile(SecretFileError::IsDirectory { .. }))` —
which is what FR-31's per-path hygiene assertions need, without seven near-identical variants.

**The signer arm is the one that would have been wrong by default.** `exit_code_for`'s signer
block ends in `_ => 1` (`errors.rs:329`), so a new `SignerError` variant silently becomes exit
**1**, and the enumerated arm above it maps every key failure to **3**. FR-13 requires a missing
or unreadable key file to be **2**. Hence an explicit arm:

```rust
AppError::Signer(e) => match e.sentinel() {
    SignerError::UserRejected | SignerError::Cancelled => 4,
    // A key *file* configuration failure is a user error (FR-13), not a crypto
    // failure — unlike every other SignerError. Explicit, above the exit-3 list.
    SignerError::KeyFile(_) => 2,
    SignerError::SignerClosed | … => 3,
    _ => 1,
},
```

placed with a one-line amendment to the module header's "3 — signer/crypto errors" comment.
`SignerError::InvalidKey` keeps its exit 3, which is what holds `run::bad_key` green.

**FR-29 message fixes.** `KeystoreError::NoTty`'s text hard-codes `--passphrase-env VAR`
(`error.rs:68`) and is asserted by substring at `passphrase.rs:307`; both change to
`--passphrase-file PATH`. The same for the two `--mnemonic-passphrase-env VAR` strings at
`keygen.rs:289` and `:389`, and the `gen.rs:623` assertion.

**FR-19, the hex-shaped-argument guard.** Applied in `local_signer_from_file` on the
`SecretFileError::NotFound` branch only, never as a pre-flight `stat` — so there is still
exactly one `open` per invocation. The argument is tested against `^(0x)?[0-9a-fA-F]{64}$` and,
on a match, replaced with an exit-2 message that names the flag and the mistake and **does not
echo the argument**.

## 8. CLI surface

`shared_args()` (`keystore_cli.rs:61`), `gen_cli.rs:122`, `sign_cmd.rs:82`, `run_cmd.rs:72`:
the `-env` args are **removed, not aliased** (FR-1), so a stale `--passphrase-env` in a script
is an unknown flag (clap exit 2). `value_name("PATH")` everywhere, and the six `override_usage`
strings are updated (FR-2).

```rust
MnemonicPassphraseForm::File {
    path: String,
    value: Zeroizing<String>,
}
```

replaces `Env { var, value }` (FR-4). The `conflicts_with` pairing moves with the id rename
(`keystore_cli.rs:87`, `:97`) and the four-form matrix is otherwise identical. The hand-written
`Debug` (`keystore_cli.rs:45-58`) keeps `path` visible and `value` `[REDACTED]` — and it stays
hand-written for a hard reason: `Zeroizing` derives `Debug`, so `#[derive(Debug)]` on this enum
would compile and print the secret.

`parse_mnemonic_passphrase_form(m: &ArgMatches, warn_out: &mut dyn Write)` gains the sink; the
caller (`load_validator_config` / `load_account_config`) already has `banner_out` in scope
(`validator_cli.rs:192`). Empty is **valid** (FR-18) — including a file holding only `"\n"`,
which FR-8 reduces to the empty string.

Config fields: `passphrase_env: String` → `passphrase_file: Option<PathBuf>` on
`ValidatorConfig` (`validator_cli.rs:43`), `AccountConfig` (`account_cli.rs:44`), `GenConfig`
(`gen_cli.rs:33`); `private_key_env_var: String` → `private_key_file: Option<PathBuf>` on
`SignConfig` and `RunConfig`. `DEFAULT_PRIV_KEY_ENV` (`sign_cmd.rs:19`) and
`is_posix_env_var_name` (`sign_cmd.rs:204`) and its `posix_env_var_name_matrix` test are deleted
with the flags they served (FR-25).

**`-` is rejected** (FR-6) by one shared helper, in the bin's neutral filesystem module:

```rust
// fs_util.rs — beside validate_output_dir / symlinked_output_dir.
/// Validates a secret-file flag argument. `-` is rejected (exit 2): stdin is
/// already claimed by `tx sign --input -` and by `validator recover`'s
/// piped-mnemonic path, and `require_tty_for_new` reasons about stdin being a
/// TTY. The message points at process substitution — `<(gpg -d pw.gpg)` — as
/// the no-disk-file pattern, and mentions `/dev/fd/N` only as the general
/// escape hatch: naming `/dev/stdin` alone would send an operator straight
/// into the collision the rejection exists to avoid.
pub(crate) fn secret_file_arg(flag: &str, value: &str) -> Result<PathBuf, AppError>;
```

## 9. Test seams

**FR-21 — the WARNING counters.** There are **six** assertions that count `WARNING` lines, not
the three the PRD names. Each must become kind-specific on R3's discriminating token
`file permissions` (which is not a flag name, so it survives a flag rename, and not a path, so
it is host-independent) or on its own kind's token:

| Site | Counts | At risk? |
|---|---|---|
| `validator_e2e.rs:495-499` | `--no-verify` | **yes** — the test will pass `--passphrase-file` |
| `validator_e2e.rs:526-530` | symlinked output dir | **yes** — same |
| `validator_cli.rs:543-548` | banner | **yes** if the case gains `--mnemonic-passphrase-file` |
| `account_cli.rs:496-500` | banner | same |
| `fs_util.rs:269-273` | unit, `Vec<u8>` sink | no — no file flag in play |
| `validator_cmd.rs:2527-2535` | unit, `FixedPassphrase` | no — same |

**Every e2e/integration test that creates a passphrase file must `chmod 600` it**, or it will
emit an FR-17 warning and break its own count. This is the FR-17 note's flip side: git cannot
store 0600 (`testdata/hoodi/passphrase.txt` is tracked `100644`), so *tracked* fixtures warn by
design and *temp* fixtures must not.

**Conversion blast radius — the largest single chunk of work in this change, and it is not a
string swap.** 64 occurrences of the three `-env` flags across 11 integration-test files:
`gen.rs` 18, `sign.rs` 12, `run.rs` 10, `validator_e2e.rs` 4, `validator_secret_hygiene.rs` 4,
`account_secret_hygiene.rs` 4, `exit_usage.rs` 3, `run_rpc.rs` 3, `e2e_live.rs` 2,
`e2e_pipeline.rs` 2, `account_e2e.rs` 1. Each `.env(KEY_ENV, PHASE3_KEY)` +
`--private-key-env KEY_ENV` pair becomes: create a file in the test's temp dir, write the
bytes, `chmod 600`, pass the path. That needs **one new shared helper in
`tests/common/mod.rs`**, beside `ethernal()`:

```rust
/// Writes `bytes` to `dir/name` at mode 0600 and returns the path. Every test
/// secret file must go through this: a 0644 file emits the FR-17 WARNING and
/// breaks the caller's own WARNING count.
pub fn secret_file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf;
```

The helper must write **without** a trailing newline by default, so the fixtures do not
silently exercise FR-8 where a test meant to exercise something else.

**Injection points.** `FileSource::new(path, warn_out)` and
`new_local_signer_from_file(path, warn_out)` both take the sink, so unit tests capture warnings
into a `Vec<u8>` with no process-level plumbing. No `Deps` struct gains a field; in particular
`ValidatorDeps`/`AccountDeps`/`GenDeps` are untouched, which keeps the ~10 existing test
constructors compiling unchanged.

**New coverage** (FR-31–FR-35): the eight error paths (not found, permission denied,
is-a-directory, empty, multi-line, `pw\r` / `pw\r\n` / `pw\r\r\n`, over-size, non-UTF-8) asserted
for exit code **and** for absence of contents in stdout/stderr/log/`Debug`; the FR-19 guard
asserted not to echo; the FR-33 FIFO test driving `tx run --signer local --rpc-url <stub>` —
which must use **RPC mode**, since that is the only path that constructed two signers; and
`ETHERNAL_TX_PRIVATE_KEY` dropped from the harness allowlist (`tests/common/mod.rs:53`) while
the `_RPC_URL`/`_FROM`/`_GAS_LIMIT` entries stay (A-1, OD-1).

## 10. Decisions

| # | Decision | Rationale | Rejected alternative |
|---|---|---|---|
| **D-1** | Read primitive in a **new leaf crate** `ethernal-secretfile` (`zeroize`, `thiserror`) | Two crates need byte-identical policy; a shared crate makes FR-10/FR-27 structural instead of conventional. Costs one `Cargo.toml` — members are globbed and every make/CI target is `--workspace` | signer→keystore (drags `rpassword` into a signing crate, inverts layering); `ethernal-core` (pulls `blst` into the audited pure-Rust keystore crate); duplication (~80 lines + error enum + wording + tests, drifting silently into a derived key) |
| **D-2** | Two entry points (`read_secret_line`, `read_secret_trimmed`), not one with a flag | FR-7 and FR-8 are genuinely different rules; a boolean parameter is selectable by accident, a function name is not | `read_secret(path, TrimMode)` |
| **D-3** | `FileSource` **validates UTF-8** at the boundary; all three consumers fail closed | No capability is lost — `std::env::var` already errors on non-UTF-8, so the replaced flag could not deliver those bytes. Closes S-B's silent U+FFFD key change. Refusing stays the reversible direction | preserve each consumer's current behavior (keeps a silent wrong-key path in S-B) |
| **D-4** | `tx run`/`tx sign` construct **one** `LocalSigner` and pass it forward; `SignConfig` holds `Option<PathBuf>`, never material | One file read; the key lives in exactly one `Mutex<[u8;32]>`; no secret in a `#[derive(Debug)]` struct — and `Zeroizing` *derives* `Debug`, so the compiler would not have caught that | put `Zeroizing<String>` in `SignConfig` behind a hand-written `Debug` (more code, one more secret copy, one more thing to get wrong) |
| **D-5** | `deposit gen` reads the passphrase file **once before the worker pool** into `InMemoryPassphrase` | `loader.load` is called per pubkey across N threads; with a file that is N concurrent opens. Also converts a mid-pool exit-3 into a fail-fast exit 2 | leave gen alone (hangs on a FIFO, wrong-passphrase on `<(...)`); memoizing decorator (needs fallible interior-mutability init; a retry on a FIFO blocks) |
| **D-6** | Two `KeystoreError` variants wrapping `SecretFileError`, not seven flattened ones | Every mode stays `matches!`-able for FR-31 without seven near-identical variants; `PassphraseFileEmpty` mirrors `EnvVarEmpty` exactly | one opaque `PassphraseFile { path, detail: String }`; a 1:1 mirror of all seven |
| **D-7** | Explicit `SignerError::KeyFile(_) => 2` arm in `exit_code_for`, not call-site mapping | The signer block's `_ => 1` would silently misclassify; one arm, one assertion, one place. Preserves "every other `SignerError` is 3 or 4" | call-site `AppError::exit2` wrapping (house style for keystore writes, but here it must be remembered at every construction site) |
| **D-8** | FR-19's guard on the `NotFound` branch | Exactly one `open` per invocation; no pre-flight `stat` to disagree with the read | pre-flight shape check before opening |
| **D-9** | Each file is read where its env counterpart is read today (I-1) | A fail-fast hoist puts the FR-17 warning before `clear_after_ceremony`, which erases it — silently disabling FR-17 with no test failing | validate all secret files at config load |
| **D-10** | **OD-6:** no deprecation window; `EnvSource` / `new_local_signer_from_env` retained, **not** `#[deprecated]` | See §10.1 | one release with `.hide(true)` + warning; delete the library items now |

### 10.1 OD-6 — recommendation

**Confirm A-3, and retain the library items un-annotated.**

- **No deprecation window.** No release of this tool has shipped, so there is nobody to
  deprecate *for*: a window's entire value is protecting existing users of a published
  interface. Its cost is real and immediate — both code paths, both sets of hygiene tests, and
  a `--passphrase-env` that still silently works, which for a secret-handling flag is strictly
  worse than a loud unknown-flag error. `CHANGELOG.md` records it as breaking (FR-37), naming
  the FR-24 zero-flag regression explicitly, and any CI job relying on it is updated.
- **Retain `EnvSource` and `new_local_signer_from_env`.** Removing them is a semver-major
  library decision that deserves its own disposition, and keeping them is what makes M-5
  ("public library items removed: 0") true. They are also genuinely useful to embedders whose
  threat model differs from a CLI's.
- **Do not add `#[deprecated]`.** A deprecation marker is a promise about a removal that has
  not been decided; making it now converts an open question into a published commitment. The
  secondary cost is real but smaller than it first looks: `EnvSource` has no user inside
  `ethernal-keystore` (its `passphrase.rs` tests cover `TermPromptSource`,
  `NewKeystorePassphrase` and `require_min_len` only) — the remaining users are the binary's
  tests, e.g. `validator_cmd.rs:1466`, which `make lint` compiles under
  `clippy --workspace --all-targets -- -D warnings`, so each would need an explicit `allow`.
  After this change `new_local_signer_from_env` may have no in-repo caller at all.
- **The substantive change is FR-28**, which is already P0: rewriting the doc comments that
  name the environment as *the* secure source and recommend `new_local_signer_from_env` for CLI
  code. That removes their preferred status without a semver event, which is exactly the
  distinction OD-6 is asking about. If the env items are later to be removed, that is a
  separate `0.x` → `0.y` decision with its own migration note.

## 11. Divergences from the PRD

1. **`deposit gen` is a second FR-22 site, and it is restructured** (D-5). FR-22 names only
   `tx run` and adds "same discipline … wherever a passphrase source is consulted twice";
   `loader.load` per pubkey across N worker threads is that case, and it is concurrent. The
   issue breakdown must budget for it.
2. **FR-21 names three WARNING-counting assertions; there are six** (§9). Two more are
   currently at risk and two are structurally immune. The requirement is unchanged; the
   inventory is corrected.
3. **The `--mnemonic-passphrase-file` permission warning is erased on `validator new` /
   `account new`** (I-2). FR-17 is met at the moment of the read; the ceremony's scrollback
   clear is pre-existing and out of scope. Called out because it is otherwise a silent partial
   failure of a P0.
4. **A missing/unreadable private-key file exits 2, where a missing env var exits 3 today.**
   FR-13 requires 2; no existing test pins the env behavior. Deliberate, and it makes all four
   flags agree.
5. **`SecretFileError` has no `Empty` variant.** FR-18's empty rule is caller policy; the
   private key needs none because an empty file is already a loud hex parse failure (S-A).
6. **FR-12b is resolved as "validate"** (D-3, §3), with the per-consumer consequence stated and
   a non-UTF-8 row added to the H9 / A5-M gates alongside OD-7's CR rows.

## 12. Risks

| # | Risk | Mitigation |
|---|---|---|
| **R-1** | A fifth crate is judged not worth it at plan review | Fallback: put the primitive in `ethernal-keystore` (public), duplicate ~80 lines in `ethernal-signer`, and add a conformance test asserting both produce identical results over the full case matrix. Strictly worse, but bounded |
| **R-2** | An implementer "improves" the design by validating secret files at config load | I-1 is written as an invariant with the reason; the FR-17 e2e test on `recover` is the tripwire |
| **R-3** | A test creates a passphrase file without `chmod 600` and an unrelated WARNING count fails | §9 states the rule; the six counters become kind-specific, so an unexpected `file permissions` line fails *its own* assertion with a clear message |
| **R-4** | `run_action`'s reordered signer construction flips an error-precedence assertion | `run::invalid_input` and `run::bad_key` are named in §6.1 and must pass unmodified; `exit_usage.rs` is re-run as part of the same issue |
| **R-5** | The FR-33 FIFO test is written without `--rpc-url` and passes vacuously | The acceptance bullet and §9 both say RPC mode is required; the test must fail if the read-once fix is reverted |
| **R-6** | Doc sweep misses one of the **58** occurrences (guide 53, README 2, `verify` skill 3) | The PRD's `rg` acceptance check is mechanical and runs in the same issue |
| **R-7** | The **64** test occurrences across 11 files are estimated as a string swap and the phase overruns | §9 states the real shape (tempdir + write + `chmod 600` + path) and mandates the `tests/common` helper first, so the 64 sites become one-line calls |

## 13. File → requirement map

| File | Requirements |
|---|---|
| `crates/ethernal-secretfile/` (new) | FR-7, FR-8, FR-9, FR-10, FR-13, FR-14, FR-15, FR-16, FR-17, FR-23, FR-12b |
| `crates/ethernal-keystore/src/passphrase.rs` | FR-18, FR-19b, FR-23b, FR-26, FR-27 |
| `crates/ethernal-keystore/src/error.rs` | FR-27, FR-29 |
| `crates/ethernal-signer/src/local.rs`, `errors.rs` | FR-7, FR-26, FR-28 |
| `bins/ethernal/src/keystore_cli.rs` | FR-1…FR-5, FR-18 |
| `bins/ethernal/src/{validator,account,gen}_cli.rs` | FR-2, FR-4, FR-6 |
| `bins/ethernal/src/{validator,account}_cmd.rs` | FR-19b, and I-1 |
| `bins/ethernal/src/gen_cmd.rs` | FR-22 (D-5) |
| `bins/ethernal/src/{sign,run}_cmd.rs` | FR-19, FR-22, FR-24, FR-25, FR-30 |
| `bins/ethernal/src/fs_util.rs` | FR-6 |
| `bins/ethernal/src/errors.rs` | FR-13, FR-27 |
| `bins/ethernal/tests/*` | FR-12, FR-21, FR-31…FR-35 |
| `docs/USER-GUIDE.md`, `README.md`, `CHANGELOG.md`, `.claude/skills/verify/SKILL.md` | FR-11, FR-20, FR-36, FR-37, FR-38 |

## 14. What explicitly does not change

Keystore JSON bytes · filenames · `0600` output mode · `create_new` write semantics · scrypt
parameters · the mnemonic ceremony and its scrollback clear · the C1–C4 verification work and
`--no-verify` · `Progress` / `PhaseReporter` · `print_key_summary` and the `keystore i/N:`
durable line · `EnvSource` and `new_local_signer_from_env` (M-5) · the `ETHERNAL_TX_RPC_URL` /
`_FROM` / `_GAS_LIMIT` value fallbacks (OD-1, A-1) · exit codes 0–5 semantics · `ethernal-core`
and `ethernal-tx` · the `--verify-with-deposit-cli` child invocation · the pre-existing
`read_to_string` residue in `RecoverMnemonicSource` (`keygen.rs:350-353`), a deliberate
out-of-scope omission recorded by FR-23 · the per-pubkey TTY prompt in `deposit gen`.

---

**Downstream:** `project-plan.md` · `issues/index.md`
