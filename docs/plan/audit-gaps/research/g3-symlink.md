# Research: G3 — Warn when the output directory is (or resolves through) a symlink (ToB Mar 2026)

## Verdict
Feasible and small, but there are two findings that change the shape of the work: (1) the naive
"`canonicalize` diverges from the given path" check **false-positives on macOS system symlinks**
(`/tmp`, `/var`, `/etc` → `/private/…`), which will break the "real dir → no warning" test on a dev
Mac (and only pass on the Linux CI runner) — prefer a **final-component `symlink_metadata` check**;
(2) `validate_output_dir` is **duplicated** (shared `key_cli` copy + a private `gen_cli` copy) and
returns `Result<(), String>` with **no writer parameter**, so the warning needs plumbing across two
sites. Confidence: **High** on the Rust detection design and both traps (verified against local
code + std semantics); **Medium** on the ToB report's exact wording (the PDF would not text-parse in
this environment — see Sources).

## Context
- **Lineage:** Trail of Bits, *ethstaker-deposit-cli Security Review*, March 2026. **Locked: warn,
  do not fail.** The vault audit note is the binding summary ("warn on symlinked output dir"); the
  file-level writes are already symlink-safe.
- **What ToB recommended (per the audit note; report PDF not parseable here [7]):** a symlinked
  *output directory* is silently followed, so keystores can land on an unexpected filesystem, a
  weaker-permission mount, or an attacker-chosen dir with no operator signal. The remediation is an
  operator **warning**, not a hard failure (failing would break legitimate symlinked-mount
  workflows). This is consistent with ToB's house style of rating such issues low/informational with
  a "surface it to the user" recommendation.

## Local grounding (read before implementing)
- `bins/ethernal/src/key_cli.rs:332` — `pub(crate) fn validate_output_dir(dir: &str) -> Result<(), String>`.
  Does `std::fs::metadata(dir)` (which **follows** symlinks), an `is_dir()` check, then
  `fs_util::probe_dir_writable`. **Imported and reused by `account_cli.rs`** (`use …key_cli::{…,
  validate_output_dir}` at `account_cli.rs:14`) — so `key new/recover` and `account new/recover`
  share this one function.
- `bins/ethernal/src/gen_cli.rs:362` — a **second, private** `fn validate_output_dir` with the same
  body, used by the `gen` (deposit-data) output-dir path. This is the "separate deposit-data command"
  the G3 scope calls out. **Both copies must gain the check** (or the detection must be centralized).
- `bins/ethernal/src/fs_util.rs` — the natural home for a shared, unit-testable detection helper
  (already holds `probe_dir_writable`; already has symlink-aware tests). It uses `create_new`/`O_EXCL`
  so the file-level writes never follow a planted symlink (H5).
- **No writer is threaded into `validate_output_dir`.** By contrast `key_cli::load_config` /
  `gen_cli::load_config` already carry a `banner_out: &mut dyn Write` (stderr in prod, `Vec<u8>` in
  tests). Simplest consistent change: give `validate_output_dir` a `warn_out: &mut dyn Write` and pass
  the existing banner/stderr writer, OR keep detection pure in `fs_util` (returns `Option<PathBuf>`)
  and let the caller emit the warning on its existing writer.

## Rust detection patterns

### Recommended: final-component `symlink_metadata` (cross-platform, false-positive-free)
```rust
// fs_util.rs — pure detection; caller does the I/O.
/// If `dir`'s final component is a symlink, returns its resolved real path.
pub(crate) fn symlinked_output_dir(dir: &Path) -> Option<PathBuf> {
    match std::fs::symlink_metadata(dir) {          // lstat: does NOT follow the final component
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(dir).ok(),
        _ => None,
    }
}
```
- `symlink_metadata` = `lstat(2)`: reports on the link itself, so `is_symlink()` is true iff the
  **path the operator typed** is a symlink. This is exactly the ToB threat ("operator points
  `--output-dir` at a symlink").
- `canonicalize` = `realpath(3)`: fully resolves to the real absolute target for the warning message.
  The path already exists (existence is checked earlier), so `canonicalize` won't error on the happy
  path.
- **No false positives** for a real directory anywhere — including macOS temp dirs — because the
  final component of a normal `mkdir`'d dir is not itself a link.

### The `canonicalize`-divergence trap (why not to compare `canonicalize(dir) != dir`)
The issue text also suggests "`canonicalize` diverges from the given path" to catch **intermediate**
symlinks. This is where it bites:
- On **macOS**, `/tmp`, `/var`, `/etc` are symlinks into `/private/…`. `canonicalize("/tmp/keys")`
  → `/private/tmp/keys` ≠ `/tmp/keys`, so the divergence check **warns on a perfectly normal dir**.
- The repo's own `tests/common::TempDir` (and `key_cli`/`fs_util` test `Tmp`) use
  `std::env::temp_dir()`, which on macOS is `$TMPDIR` under `/var/folders/…` (a `/var` symlink). So a
  test asserting **"real dir → no warning"** would **pass on the Linux CI runner (`ubuntu-latest`)
  but fail on a developer's Mac** under `make test`. That is a nasty, environment-specific red-herror.
- Divergence also fires for any non-absolute or non-normalized input (`./keys`, trailing `/`, `..`),
  none of which is a symlink.

**Guidance — and does final-component-only still earn the ETHSTAKER-3 symlink-row flip? Yes.** SM-3's
acceptance evidence tests exactly two cases: *symlinked output dir → one warning naming given →
resolved path*, and *real dir → warning-free*. It does **not** test intermediate-component symlinks.
So the final-component `symlink_metadata` check is **sufficient** to satisfy SM-3 and flip the row —
and it is precisely the case the ToB recommendation names (operator points `--output-dir` at a
symlink). Treat the intermediate-symlink question as a **conscious planner choice**, not a silent
requirement drop:
- **(A) Final-component only (recommended).** `symlink_metadata(dir).is_symlink()`. Zero false
  positives on any platform; satisfies SM-3; matches the ToB threat. Simplest, and passes on both the
  Linux CI runner and a dev Mac.
- **(B) Also intermediate.** Walk ancestor components with `symlink_metadata` (do **not** compare
  `canonicalize(dir)` to the raw input string). This adds the "unexpected mount / attacker-planted
  ancestor" signal on the real Linux bastion targets — but macOS `/var`,`/tmp` ancestors trip it, so
  the ancestor walk **and its test** must be `#[cfg(not(target_os = "macos"))]`-gated or fed a
  canonicalized base dir. Given warn-only semantics and the mostly-Linux target, (B) is a reasonable
  upgrade, (A) is the safe default — but note PRD G3-1's literal "final AND canonicalize-divergence"
  wording is *internally inconsistent* with SM-3 on macOS, so the planner should pick (A) or (B)
  explicitly rather than implement G3-1 verbatim.

### TOCTOU: not a concern here, and worth stating so
The check is **advisory only** and does not gate or redirect the write. The security guarantee comes
from the **file-level** `write_new_0600` (`O_EXCL` create + tmp+fsync+`hard_link` publish + `0600` +
refuse-overwrite), which already refuses to follow a symlink planted at the keystore filename (proven
by `fs_util::symlink_probe_does_not_touch_canary_target`). So a dir swapped between the warn-time
check and write time cannot turn into a new vulnerability — it only makes the *warning* potentially
stale. Therefore the warn-only check needs **no** TOCTOU hardening; do not over-engineer it into a
locked-fd dance. (This matches invariant S-3: the check "never follows an untrusted path beyond
`canonicalize` and never changes where or how the file is written.")

## Implications for implementation
1. **Two call sites, not one.** Add the check to `key_cli::validate_output_dir` (covers key + account)
   **and** `gen_cli::validate_output_dir`. Best: put detection in `fs_util::symlinked_output_dir`
   (pure, unit-tested there) and call it from both. This turns G3 from a "one-liner" into a shared
   helper + 2 call-site edits + the warning-writer plumbing.
2. **Plumb a writer** (or return the resolved path). `validate_output_dir` has no `&mut dyn Write`
   today; either add `warn_out: &mut dyn Write` (mirroring `load_config`'s `banner_out`, threaded from
   the two/three `load_config`s) or have `validate_output_dir` return the `Option<PathBuf>` for the
   caller to warn on its existing stderr. The former keeps the warning next to validation and is
   directly unit-testable with a `Vec<u8>`.
3. **Prefer `symlink_metadata` over `canonicalize`-divergence** to avoid the macOS `/tmp`,`/var`
   false positives that would make `make test` red on dev Macs while green on CI. If both are used,
   the "real dir → no warning" test must use a canonicalized base dir or be Linux-gated.
4. **Warning content:** name **both** the given path and the resolved real path (G3-2), on stderr, in
   the repo's existing warning tone (see the `--help`/USER-GUIDE warning style already used for the
   raw-mnemonic-passphrase caveat). Exactly one warning line per run (test asserts count == 1).
5. **No behavior change beyond the warning** (S-2/S-3): still `O_EXCL` + link-publish + `0600` +
   refuse-overwrite; the symlink check only reads metadata and emits text.
6. **Test shape:** create a real dir (canonicalized) → assert no warning; `std::os::unix::fs::symlink`
   a link → the real dir, pass the link as `--output-dir` → assert exactly one warning naming
   link → target. The repo already has the `symlink`-in-tests idiom in `fs_util.rs`
   (`symlink_probe_does_not_touch_canary_target`) to copy.

## Sources
[1] [Rust std — `fs::symlink_metadata`](https://doc.rust-lang.org/std/fs/fn.symlink_metadata.html) — `lstat`, does not follow the final symlink; `FileType::is_symlink`. Official docs.
[2] [Rust std — `fs::canonicalize`](https://doc.rust-lang.org/std/fs/fn.canonicalize.html) — `realpath`, resolves all symlinks, requires the path to exist, returns absolute path. Official docs.
[3] macOS filesystem layout: `/tmp`, `/var`, `/etc` are symlinks into `/private` (per `hier(7)` / Apple FS layout) — the source of the `canonicalize`-divergence false positive. General platform knowledge (no single URL; verifiable via `ls -l /tmp /var`).
[4] Local: `bins/ethernal/src/key_cli.rs:332` (`validate_output_dir`, shared by account via `account_cli.rs:14`), `bins/ethernal/src/gen_cli.rs:362` (private duplicate), `bins/ethernal/src/fs_util.rs` (`probe_dir_writable`, `O_EXCL` symlink-safe probe + symlink test idiom). Primary (repo source, read this session).
[5] `docs/plan/keygen/hardening-plan.md` H5 / K3-L4 — prior symlink-safety work on the writability probe (`create_new`/`O_EXCL`), referenced by the PRD. Repo doc.
[6] Vault audit note — *Audit: ethernal Implementation vs Known deposit-cli and EOA Keystore Issues* (`1.Projects/ethernal/202607181903…`) — binding summary of the ToB Mar 2026 symlink recommendation ("warn"). Primary (project audit).
[7] Trail of Bits, *ethstaker-deposit-cli Security Review*, March 2026 — [trailofbits/publications `reviews/2026-03-ethstaker-deposit-cli-securityreview.pdf`](https://github.com/trailofbits/publications/blob/master/reviews/2026-03-ethstaker-deposit-cli-securityreview.pdf). Canonical source for the exact recommendation wording/severity, **but the PDF returned as non-text binary via fetch and could not be parsed here** — the implementer should open it directly to lift the finding ID + exact phrasing for the audit-row flip. Confidence on exact wording is Medium pending that.
