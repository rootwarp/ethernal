# Phase 3 — Tx pipeline (M3: unsigned + signed goldens byte-identical, offline path)

## R3-1 — `tx` offline (3 pts, stream A, deps: R2-1)

**Scope:** Port `go/internal/tx/{types,abi,validation,builder,errors}.go` →
`crates/tx/src/`. `UnsignedTx` (serde camelCase, hex-string quantities, `From` omitempty,
`type: "0x2"`); `pack_deposit` 420-byte ABI encoding (selector 0x22895118, offsets
128/224/288); `validate` (chain ID ≠ 0, amount == 32_000_000_000 Gwei, zero-field
detection, WC prefix 0x00/0x01/0x02 with bytes 1–11 zero for 01/02); static builder path
(all of fee/tip/nonce/gas required when no RPC → per-field sentinel errors); value fixed
at 32 ETH wei hex. Error enum variants mirror every Go sentinel.

**Acceptance:** `abi_test.go` + `validation_test.go` + static-mode `builder_test.go` cases
pass; builder output equals `testdata/phase2/holesky/unsigned_tx_golden.json` byte-for-byte
via `golden_test.go` port.

## R3-2 — `tx` RPC (4 pts, stream A, deps: R3-1)

**Scope:** Port `rpc_client.go` + `redact.go` + RPC half of `builder.go`. `EthRpc` trait
(tip, base fee, pending nonce, estimate gas, chain ID) + `EthBroadcaster` trait (send raw,
receipt-once, chain ID); hand-rolled JSON-RPC over ureq (http/https only; ws:// → clear
dial error): eth_chainId, eth_maxPriorityFeePerGas, eth_getBlockByNumber(latest).baseFeePerGas,
eth_getTransactionCount(pending), eth_estimateGas, eth_sendRawTransaction,
eth_getTransactionReceipt (null result → Ok(None)). Resolution: chain-ID guard
(mismatch → sentinel, call errors warn-and-continue), tip → suggest, maxFee →
2·baseFee + tip, nonce → pending (requires From), gas → estimate·6/5. URL redaction:
`safe_url` (scheme://host or `[redacted-url]`) + `redact_url_string` at the log boundary
scrubbing raw and quoted URL forms from rendered errors.

**Acceptance:** RPC-mode `builder_test.go` + `rpc_client_test.go` + `redact_test.go` cases
pass with a mock RPC; no full URL ever appears in any error Display output (ureq errors
included).

## R3-3 — `signer` local (3 pts, stream A, deps: R3-1)

**Scope:** Port `go/internal/signer/{signer,types,errors,parse,local}.go` →
`crates/signer/src/`. `Signer` trait (sign/name/requires_user_interaction/close);
`parse_unsigned_tx` (hex field decoding, chain-ID-zero sentinel); `LocalSigner`: key from
env var (name-only in errors), k256 validation, zeroize-on-close, closed-flag; EIP-1559
signing: hand-rolled RLP (typed envelope `0x02 || rlp(...)`, empty access list), keccak256
sig-hash, RFC6979 low-s recoverable signature, y-parity v as decimal "0"/"1", r/s as
0x-hex big-int text (no leading zeros), keccak tx hash, sender recovery + self-check,
EIP-55 checksummed `From`; `SignedTx` serde shape matching Go (`unsigned`, `from`, `hash`,
`r`, `s`, `v`, `rawRLP`); `Address()` on concrete LocalSigner only.

**Acceptance:** `local_test.go` + `local_internal_test.go` + `sign_test.go`-level vectors
pass; signing `testdata/phase3/holesky/unsigned_tx.json` with `private_key.txt` equals
`signed_tx_golden.json` byte-for-byte.

## R3-4 — `signer` ledger (3 pts, stream B, deps: R3-3)

**Scope:** Port `ledger*.go`. `LedgerWallet`/`LedgerHub` traits mirroring the Go seam;
orchestration: discovery (`NoDevice`), open + status (`AppNotOpen` via APDU 6e00/6e01/6d00 +
textual heuristic), derive m/44'/60'/0'/0/0, confirmation prompt to stderr, error
classification order chain-ID-mismatch (6a80/6a81) before user-rejected (6985/textual);
close idempotent. Real transport behind `ledger` cargo feature: hidapi + Ethereum-app APDU
sign (chunked, path-prefixed), y-parity normalization. Without the feature, constructor
returns `LedgerNotSupported` (parity with non-CGO Go builds).

**Acceptance:** `ledger_internal_test.go` mock cases ported and green; `--features ledger`
compiles; hardware validation explicitly deferred (same caveat as Go TODO(3.6)).

## R3-5 — bin `build` + `sign` (3 pts, stream A, deps: R3-1, R3-2, R3-3)

**Scope:** Port `config.go`, `build` command from `main.go`, `sign.go` →
`bins/eth-deposit/src/`. Config load flag>env>default (ETH_DEPOSIT_TX_* vars), strict
--from parsing (20-byte, no silent truncation), --gas-limit/--nonce/fee parsing with
verbatim messages; `require_from_for_rpc` gate; offline default fill (250k gas / 20 gwei /
1 gwei / nonce 0); input from file or `-` stdin; output stdout or file (unsigned 0644,
signed 0600); sign: signer local|ledger, POSIX env-var-name validation, prompt line for
interactive signers.

**Acceptance:** `config_test.go` + `buildrpc_test.go` + `sign_test.go` command-level cases
pass; offline build of `testdata/phase2/holesky/deposit_data_single.json` reproduces the
unsigned golden.
