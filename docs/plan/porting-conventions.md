# Porting conventions — Go → Rust `eth-deposit`

Binding rules for every issue in `docs/plan/issues/`. The Go tree (`go/`) is the
reference implementation; when in doubt, match its observable behavior exactly.

## Behavior parity

- **Error messages verbatim.** Go error strings are part of the observable contract
  (tests assert substrings; operators grep logs). Port `fmt.Errorf` texts word-for-word,
  including prefixes like `"deposit: validate: …"`, `%q` quoting style, and hex casing.
  Wrapped-error rendering: Go `%w` chains render as `"outer: inner"`; model with
  thiserror `#[error("outer: {0}")]` or explicit `source` + Display that concatenates.
- **Go sentinels → enum variants.** Every `errors.New` sentinel becomes a dedicated
  variant on that module's thiserror enum (e.g. `TxError::RpcDial`,
  `KeystoreError::WrongPassphrase`). `errors.Is` call sites become `matches!` on the
  variant. Never collapse two sentinels into one variant — the exit-code map (R4-3)
  distinguishes them.
- **JSON byte-identity.** serde struct-field declaration order = Go struct order.
  Compact output via `serde_json::to_vec`, pretty via `to_vec_pretty` (2-space indent,
  matches `json.MarshalIndent(v, "", "  ")`) + trailing `\n` where Go appends one.
  Hex: lowercase; Launchpad entry fields unprefixed, tx fields 0x-prefixed.
  `omitempty` → `#[serde(skip_serializing_if = …)]`. Parsers tolerate unknown/missing
  fields like `encoding/json` (use `#[serde(default)]`, no `deny_unknown_fields`).
- **Exit codes** are the contract: 0 ok, 1 internal, 2 user/config, 3 signer/crypto,
  4 user abort, 5 broadcast/RPC. Nothing may `process::exit` except `main`.
- **Security invariants:** key material never in errors/logs/argv; zeroize secrets
  (`zeroize` crate) on drop/close; RPC URLs only ever logged through
  `safe_url`/`redact_url_string`; output files with secrets/signatures are mode 0600.

## Code style

- Layout: one Go file → one Rust module file of the same stem where sensible.
- Port doc comments (translate Go idioms; keep the explanatory content — these comments
  carry the spec).
- Naming: Go `CamelCase` fn → Rust `snake_case`; keep the same words
  (`ComputeSigningRoot` → `compute_signing_root`).
- Fixed-size byte arrays stay fixed-size: `[u8; 48]`, `[u8; 96]`, `[u8; 32]`, `[u8; 20]`,
  `[u8; 4]`.
- Wei quantities: `u128`. Gas/nonce/chain-id: `u64`. `*uint64` optionals → `Option<u64>`.
- Cancellation: `eth_deposit_core::cancel::CancelToken` replaces `context.Context`;
  check between units of work; cancelled → the module's `Cancelled` variant (maps to
  exit 4).
- No new dependencies beyond the workspace `Cargo.toml` list without updating it and
  noting why in the issue.
- `unsafe` only where a dependency forces it (none expected).

## Tests

- Port Go tests case-by-case; keep Go test names in a comment above each Rust test
  (`// Go: TestParsePubkeys_MixedPrefix`).
- External (black-box) Go tests → `crates/<c>/tests/*.rs`; internal (white-box)
  `_internal_test.go` → `#[cfg(test)] mod tests` in the module file.
- Fixture paths: relative to crate root (`crates/keystore/testdata/…`) or workspace
  `rust/testdata/…` via `env!("CARGO_MANIFEST_DIR")`.
- Binary-level tests use `env!("CARGO_BIN_EXE_eth-deposit")` + `std::process::Command` —
  no assert_cmd dependency.
- A test that cannot be ported meaningfully (e.g. depends on Go runtime specifics) is
  dropped with a `// NOT PORTED: <reason>` note in the module's test file.

## Definition of done (every issue)

1. `cargo test -p <crate>` green; `cargo check` green workspace-wide.
2. `cargo clippy -p <crate> -- -D warnings` clean.
3. Ported test coverage matches the Go file list for the scoped packages.
4. Any deliberate divergence documented in the issue file under a `**Divergence:**` note.
