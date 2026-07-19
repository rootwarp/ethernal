# Changelog

All notable changes to tools in this repository are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## Repository

### Restructured to Rust-only - 2026-07-17

The multi-language layout (`go/`, `python/`, `rust/`) is retired. The Rust
workspace — the completed port of `eth-deposit` (now `ethernal`), byte-identical on the shared
golden fixtures — moved from `rust/` to the repository root, and the Go and
Python trees were removed (recoverable from git history; the Go v1.0.0 tag and
its release notes remain on GitHub).

#### Removed

- `go/` — the reference implementation, retired after the Rust port reached M5
  (full command parity, ported test suites, byte-identity gates green).
- `python/` — scaffolding only; never shipped any code.
- `.goreleaser.yaml`, `.github/workflows/release.yml` — the CGO-based Go release
  pipeline. A Rust release pipeline is not set up yet.
- `.github/workflows/eth-deposit-e2e.yml` — replaced by `ci.yml` (clippy,
  rustfmt, tests, mock E2E, ledger-feature build check).
- `rust/scripts/diff-go.sh` and the `diff-go` make target — the Go binary they
  compared against no longer builds from this tree.
- `scripts/bin/eth-deposit-gen.sh`, `scripts/validate-readme-examples.sh` —
  wrappers around the removed Go build.
- `RELEASE_NOTES_v1.0.0.md` — Go-release document; preserved in git history.

#### Changed

- `Cargo.toml`, `crates/`, `bins/`, `testdata/`, `Makefile`, docs: moved from
  `rust/` to the repository root (paths inside the workspace are unchanged).
- `go/docs/USER-GUIDE.md` → `docs/USER-GUIDE.md`, updated for the Rust binary.
- `scripts/devnet/` is kept as-is (language-agnostic Docker devnet).

---

## ethernal

> **Renamed from `eth-deposit` (2026-07-18).** The CLI binary, crates, and operator
> env vars now use the `ethernal` product name. Sections below that still say
> `eth-deposit` are historical (pre-rename) unless noted.

### ethernal (unreleased) — rename eth-deposit → ethernal

#### Breaking

- **Binary:** `eth-deposit` → **`ethernal`** (`bins/ethernal`, `target/release/ethernal`).
- **Crates / dirs:** packages `eth-deposit-{core,keystore,signer,tx}` and paths
  `crates/{core,keystore,signer,tx}` → packages **`ethernal-*`** under
  **`crates/ethernal-*`**.
- **Env vars (keep `_TX_` middle segment):**

  | Old | New |
  |---|---|
  | `ETH_DEPOSIT_TX_*` | `ETHERNAL_TX_*` |
  | `ETH_DEPOSIT_TX_PRIVATE_KEY` | `ETHERNAL_TX_PRIVATE_KEY` |
  | `ETH_DEPOSIT_VERSION` / `_COMMIT` / `_DATE` | `ETHERNAL_VERSION` / `_COMMIT` / `_DATE` |

- **Writability probe file:** `.eth-deposit-probe-<pid>` → `.ethernal-probe-<pid>`.
- **GitHub repository (R6):** `rootwarp/eth-utils` → **`rootwarp/ethernal`**.

No dual-accept of old binary/env names (tool still unreleased).

---

### ethernal (unreleased) — `account` namespace (Web3 v3 EOA keystores)

Purely **additive** — the `key` / `gen` deposit surface is unchanged (U-3).

#### Added

- **`ethernal account new`** — generates a fresh 24-word BIP-39 mnemonic (OS CSPRNG),
  runs a TTY-only display-once + full re-entry ceremony, then writes Web3 Secret
  Storage **v3** scrypt EOA keystores at BIP-44 `m/44'/60'/0'/0/i` under
  `--output-dir` (geth-style `UTC--…` filenames, mode `0o600`). Non-TTY
  stdin/stdout → exit 2 before any entropy is drawn. Stderr summary lists
  EIP-55 addresses.
- **`ethernal account recover`** — rebuilds v3 EOA keystores from an existing
  12–24-word mnemonic (interactive TTY prompt or piped stdin). Supports
  `--start-index` / `--count` for partial ranges. No ceremony (mnemonic already
  exists).
- **Three-form BIP-39 mnemonic passphrase** on both `account` subcommands (same
  shape as `key`): raw `--mnemonic-passphrase VALUE`,
  `--mnemonic-passphrase-env VAR`, bare `--mnemonic-passphrase` (prompt;
  double-entry confirm on `account new`), or omit for empty (default). Distinct
  from the keystore passphrase (`--passphrase-env`). **Security:** raw `VALUE`
  is visible in `ps` and shell history — prefer env or prompt for high-value
  mnemonics (documented in `docs/USER-GUIDE.md`).
- **v3 raw-passphrase interop (C-4):** the keystore passphrase is fed to scrypt
  as **raw UTF-8 bytes (no NFKD)**, matching geth/MetaMask. Distinct from
  EIP-2335 NFKD normalization used by `key`.

#### Documentation

- `docs/USER-GUIDE.md`: new "Create EOA keystores (`ethernal account`)" section —
  ceremony, flags, `key` vs `account` (v3 vs EIP-2335), raw mnemonic-passphrase
  `ps`/history note, and the v3 no-NFKD interop rule.
- `README.md`: `account new` / `account recover` in the command list; v3 vs
  EIP-2335 note; layout/notable-details rows.

---

## eth-deposit (historical section titles)

### eth-deposit (unreleased) — keygen + withdrawal credentials

#### Added

- **`ethernal key new`** — generates a fresh 24-word BIP-39 mnemonic (OS CSPRNG),
  runs a TTY-only display-once + full re-entry ceremony, then writes EIP-2335 v4
  scrypt signing keystores (`m/12381/3600/i/0/0`) under `--output-dir`. Non-TTY
  stdin/stdout → exit 2 before any entropy is drawn.
- **`ethernal key recover`** — rebuilds keystores from an existing 12–24-word
  mnemonic (interactive TTY prompt or piped stdin). Supports `--start-index` /
  `--count` for partial ranges. No ceremony (mnemonic already exists).
- **Three-form BIP-39 mnemonic passphrase** on both key subcommands: raw
  `--mnemonic-passphrase VALUE`, `--mnemonic-passphrase-env VAR`, bare
  `--mnemonic-passphrase` (prompt; double-entry confirm on `key new`), or omit
  for empty (default). Distinct from the keystore passphrase (`--passphrase-env`).
  **Security:** raw `VALUE` is visible in `ps` and shell history — prefer env or
  prompt for high-value mnemonics (documented in `docs/USER-GUIDE.md`).
- **`gen --withdrawal-address ADDR`** — emits real 0x01 execution-address
  withdrawal credentials (`0x01 ‖ 11 zero bytes ‖ addr20`). Address must be a
  correctly mixed-case **EIP-55** checksum; lowercase or checksum mismatch →
  exit 2. Intentional asymmetry vs `build`'s `--from`, which remains
  lenient (any-case 20-byte hex; `run` has no `--from`).

#### Breaking

- **`gen` requires an explicit withdrawal choice.** Invoking `ethernal gen`
  without `--withdrawal-address` exits 2 with a clear message (require-choice
  gate). There is no default / placeholder credential path for operators. Update
  scripts and goldens that previously called `gen` without the flag.

#### Changed (hardening)

- **Invalid mnemonic word reporting (`key recover`):** unknown BIP-39 word errors
  now report the **1-based word position** only; the failing token is never
  echoed to stderr or logs (secret-hygiene / S-2).
- **`gen` zero-address reject:** the all-zero withdrawal address is rejected
  (exit 2). Success banners echo the withdrawal address and derived credentials
  for operator confirmation.
- **Non-UTF-8 mnemonic passphrase:** invalid UTF-8 in a mnemonic passphrase now
  fails closed with exit 2 instead of lossy-decoding into a different seed.
- **Same-second keystore filename collision:** concurrent writes that would
  collide on the same-second timestamp suffix retry with a unique name rather
  than failing.
- **Hostile keystore scrypt ceiling:** decrypt/load enforces an upper bound on
  scrypt parameters so a malicious keystore cannot force unbounded CPU/memory
  during passphrase verification.
- **Index-range overflow (`key new` / `key recover`):** `--start-index` +
  `--count` that would overflow is rejected up front (exit 2) with **zero**
  keystore files written (no partial write-then-fail).
- **`PassphraseTooShort` wording:** the minimum-length error reports **bytes**
  (UTF-8 length after EIP-2335 normalization), not "characters".

#### Security / hardening (operator-facing notes)

- SIGINT cancel-token init order and atomic keystore write (parent-dir fsync /
  no 0-byte stub window) tightened on the write path; no CLI flag or message
  changes.

#### Documentation

- `docs/USER-GUIDE.md`: new "Step 0 — create validator keys" covering `key new` /
  `key recover`, passphrase flows, the raw-mnemonic-passphrase `ps`/history note,
  env-var lifetime (`--passphrase-env` / `--mnemonic-passphrase-env` persist for
  the shell session; `export VAR=secret` can also land in shell history — prefer
  a dedicated session), and the EIP-55 strict-vs-lenient asymmetry
  (`--withdrawal-address` vs `build`'s `--from`).
- `README.md`: command list, quickstart, and divergence table updated for `key`
  and required `--withdrawal-address`.

---

### eth-deposit (unreleased) - 2026-07-12

**Breaking change:** `eth-deposit-gen` and `eth-deposit-tx` are merged into a single
`ethernal` binary with five subcommands: `gen`, `build`, `sign`, `run`, `send`.
The two old binary names are retired — there is no compatibility shim or alias.
This lands as unreleased (no tag cut yet); see below for why this was a cheap time
to do it.

#### Why

- `eth-deposit-gen` had one real tagged release (`v1.0.0`); `eth-deposit-tx`'s
  "[eth-deposit-tx 0.1.0]" entry below was never actually tagged — `git tag -l`
  only ever showed `v1.0.0`, and `release.yml`'s `tags: ["v*"]` trigger wouldn't
  have matched the scoped tag format that entry references anyway. Merging cost
  nothing for tx's users because it never shipped a versioned release.
- The two tools already shared one Go module, one `internal/` package tree, and
  documented each other in their own `--help` text (`build`'s description already
  pointed users at `eth-deposit-gen`'s output). The gap between "two binaries that
  hand off a JSON file" and "one binary with five subcommands" was mostly ceremony.
- Before merging, the two tools' CGO dependency chains were verified to co-link
  cleanly: a throwaway program importing both `herumi/bls-eth-go-binary` (BLS,
  used by `gen`) and `go-ethereum/accounts/usbwallet` (Ledger USB/HID, used by
  `sign`/`run`) was built and run natively (darwin/arm64), then cross-compiled to
  all 4 release targets (linux amd64/arm64 via zig cc, darwin amd64/arm64 via
  native/cross `cc`) — all four linked and ran with no symbol conflicts.

#### Known tradeoff

- `ethernal` now ships as one binary carrying both the offline BLS/keystore
  code path (`gen`) and the online RPC-broadcast/USB code path
  (`build`/`sign`/`run`/`send`). An air-gapped keygen-only deployment now
  receives (but doesn't execute) the networking and Ledger USB code it used to
  not have at all. This was an explicit, informed tradeoff in favor of a single
  binary and release pipeline over preserving that separation as a hard
  guarantee — see the two sections below for what each half used to ship alone.

#### Changed

- `internal/cli` (gen's flag/validation wiring) is now wired in as a subcommand
  (`Name: "gen"`) rather than the process root; its former custom root help
  template's Examples section moved into `Description` text, matching the
  pattern `build`/`sign`/`run`/`send` already used.
- Exit codes are unchanged and were already compatible: gen's 0/2/3/4 (+1
  fallback) is a subset of tx's 0/1/2/3/4/5 scheme; both are now handled by one
  `ExitCodeFor` in `exit.go`.
- `.goreleaser.yaml`: 8 build entries (4 gen + 4 tx) collapsed to 4; one archive
  (`ethernal_<os>_<arch>.tar.gz`) instead of two. One SBOM per platform
  instead of one per tool per platform.
- CI: `eth-deposit-gen.yml` retired; the surviving e2e workflow and `release.yml`
  now test the whole module instead of per-tool subdirectories.
- `go/Makefile`: single `build` target (`bin/eth-deposit`) replaces `build`
  (gen) + `build-tx` (tx).
- `go/docs/USER-GUIDE.md`: updated throughout to the merged command shape
  (`ethernal gen`, `ethernal build`, etc.).

---

## eth-deposit-tx

### [eth-deposit-tx 0.1.0] - 2026-05-18

First release. Builds, signs, and broadcasts Beacon Chain deposit transactions
from Launchpad-compatible deposit data JSON. Use v0.1.0 because Ledger heuristics
against real hardware are not yet refined — that refinement is tracked for v0.2.0.

#### Added

- **Subcommands:** `build`, `sign`, `run`, `send` wired via `urfave/cli/v2`. `run` is a convenience alias for `build + sign` on the same machine. `send` broadcasts a signed transaction via JSON-RPC.
- **Local signer:** `--signer local` reads the private key from `ETHERNAL_TX_PRIVATE_KEY` (env-var only; never a CLI flag), signs an EIP-1559 transaction, and zeroizes the key on close.
- **Ledger signer:** `--signer ledger` signs via a connected Ledger hardware wallet using the go-ethereum `usbwallet` transport. Key never leaves the device.
- **Networks:** Holesky, Sepolia, Hoodi, and Mainnet. Mainnet safety: `send` fetches the chain ID from the RPC node and refuses broadcast if it mismatches the signed tx's chain ID, preventing accidental cross-network broadcast. Users must type the network name interactively before `eth_sendRawTransaction` is called.
- **Static fee/gas/nonce:** all gas and nonce flags can be supplied manually for fully offline / air-gapped operation (`build` with no `--rpc-url`).
- **RPC fee/gas/nonce resolution:** when `--rpc-url` is provided, `build` fetches the current nonce, base fee, and suggests EIP-1559 tip cap from the node.
- **Double-confirmation broadcast:** `send` requires the user to type the network name to confirm before `eth_sendRawTransaction` is called, even in non-interactive mode.
- **Receipt polling:** after a successful broadcast `send` polls the RPC for the transaction receipt and prints the block number and tx hash.
- **Exit codes:** 0 success, 1 internal error, 2 user/config error, 3 signer/crypto error, 4 user abort (SIGINT or Ledger rejection), 5 broadcast/RPC error.
- **Stdin/stdout pipe support:** `--input-file -` and `--output -` for full Unix-pipe compatibility across all subcommands.
- **Multi-entry JSON:** warns on stderr when a JSON array has more than one entry and defaults to `--index 0`; `--index N` selects a specific entry.

#### Security

- Private key accepted only via environment variable (`ETHERNAL_TX_PRIVATE_KEY`); a POSIX-name validator rejects accidental raw-hex values passed as the flag name (exit code 2).
- Key bytes are zeroized immediately on `LocalSigner.Close()` (verified by `TestLocalSigner_Close_ZeroizesKey`).
- Signed output files written with permissions `0o600`.
- No key material appears in error messages, logs, or help text.
- Ledger is always promoted as the preferred path; local signer help text calls it "development and CI only".
- Sentinel-based error wrapping (`errors.Is`) maps signer failures to typed exit codes without leaking internals.
- **Synthetic test key callout:** the test private key in `testdata/` is used only for E2E mock tests and is clearly marked as non-production material.

#### Documentation

- `go/docs/USER-GUIDE.md` — single comprehensive user guide for both `eth-deposit-gen` and `eth-deposit-tx`: install, quickstart, full command reference, networks, exit codes, security, recipes, troubleshooting.
- Repo-level `README.md` updated to list both tools and the end-to-end flow.

#### Known Limitations

- Ledger heuristics (`isUserRejectedErr`, `isChainIDMismatchErr`) are pattern-based string matches on go-ethereum APDU error codes; not yet validated against all firmware versions on real hardware. Tracked for v0.2.0.
- CGO is required (go-ethereum `usbwallet` and `herumi/bls-eth-go-binary`). Pure-Go / `CGO_ENABLED=0` builds are not supported.
- Windows is not supported (no CI runner; operator use case is Linux/macOS only).
- Goroutine leak on context-cancelled Ledger sign: the APDU exchange goroutine runs until the device responds or times out (accepted trade-off; single-invocation, bounded).

---

## eth-deposit-gen

### [eth-deposit-gen 1.0.0] - 2026-05-17

#### Added

- **Networks:** Hoodi testnet support (fully enabled, golden-tested). Mainnet support enabled behind `--i-understand-this-is-mainnet` safety gate; the flag and an uppercase `MAINNET` banner are required before any mainnet signing occurs.
- **`--keystore-dir`:** Directory-based keystore loading; scans a directory of EIP-2335 v4 keystores and loads only the keystore matching each requested pubkey — no decryption of unneeded files.
- **`--parallel N`:** Bounded parallel signing worker pool (default 1); deterministic output order regardless of parallelism level; benchmarked at ≥ 200 entries/sec.
- **`--dry-run`:** Print deposit JSON to stdout without writing a file; sha256 on stderr matches stdout bytes.
- **`--verbose` / `--json-logs`:** Structured `log/slog` logging; text or JSON handler; signing-critical packages contain zero log statements.
- **`--verify-with-deposit-cli`:** Optional post-generation cross-check via `deposit verify --input-file` (requires `staking-deposit-cli >= 2.7.0`).
- **Progress indicator:** `signing: <i>/<n>` on TTY stderr for batches > 5; 10%-boundary `slog.Info` on non-TTY.
- **Exit codes:** 0 success, 2 configuration/user errors, 3 crypto/verification failures, 4 SIGINT.
- **Pre-built binaries:** darwin/amd64, darwin/arm64, linux/amd64, linux/arm64 with `checksums.txt` and per-artifact SBOM (SPDX 2.3).

#### Security

- Internal audit signed off 2026-05-17: SSZ chunk tables, BLS boundary sizes (pubkey 48 bytes, signature 96 bytes, secret 32 bytes), 10-step deposit pipeline, zeroization on every error path, atomic output write (temp + fsync + rename). (Audit document removed in subsequent docs cleanup; commit history preserves it.)
- `GOFLAGS=-mod=readonly` enforced in all CI jobs (both `eth-deposit-gen.yml` and `release.yml`).
- Atomic file write: `.tmp` file + `f.Sync()` + `os.Rename` — no partial file is ever visible to the OS.
- BLS secret key zeroized immediately after signing via `key.Zeroize()`; passphrase bytes zeroized via `defer zeroizeBytes` with `runtime.KeepAlive` guard.

---

[eth-deposit-tx 0.1.0]: https://github.com/rootwarp/ethernal/releases/tag/eth-deposit-tx/v0.1.0
[eth-deposit-gen 1.0.0]: https://github.com/rootwarp/ethernal/releases/tag/v1.0.0
