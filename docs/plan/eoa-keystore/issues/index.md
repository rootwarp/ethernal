# EOA keystore issues — summary

Sprint-ready issue files for the EOA keystore feature (`account new` / `account recover` — secp256k1
BIP-32/BIP-44 derivation → Web3 Secret Storage v3 keystores). Detail derived from the approved
[`../project-plan.md`](../project-plan.md), [`../architecture.md`](../architecture.md),
[`../prd.md`](../prd.md), and [`../research/`](../research/). **13 pointed issues · 21 points · +1
manual session.** Phase files: [`phase-a1.md`](phase-a1.md) · [`phase-a2.md`](phase-a2.md) ·
[`phase-a3.md`](phase-a3.md) · [`phase-a4.md`](phase-a4.md) · [`phase-a5.md`](phase-a5.md).

Tags are `[A#-#]` (letter `A` = account; never collides with keygen `K`/`H`). Per-issue commits on
`develop`, **fast-forward** merges, every merge green (`make test && make lint`).

## All issues

| ID | Title | Pts | Stream | Depends on | Milestone |
|---|---|---|---|---|---|
| A1-1 | `core::hd_secp256k1` primitive — `k256` dep + `zeroize`-feature decision (R1), `ExtendedPrivKey` master/`derive_child` (both CKDpriv branches), `Bip32Error`, BIP-32 TV1 (keys + chain codes) | 3 | A | — | M-A1 |
| A1-2 | `Bip44Path` + `derive_path` fold + `secret_bytes` + Ethereum BIP-44 `abandon` **secret** vector (`1ab42cc4…`/`9a983cb3…` vs `cast`) | 1 | A | A1-1 | M-A1 |
| A2-1 | `sha3` dep + `crypto::v3_mac` (keccak) + `keystore::encrypt_v3` + `ScryptParams` + v3 `Serialize` structs + G3 byte-gate + **C-4 non-ASCII raw-passphrase guard** + round-trip + `len!=32` reject | 3 | B | — | M-A2 |
| A2-2 | `v3_filename` — hand-rolled `civil_from_days` UTC conversion + fixed vector | 1 | B | A2-1 | M-A2 |
| A3-1 | `signer::secret_to_address` (factor + export, `0<k<n` guard) + abandon **address** vector (`0x9858…`/`0x6Fac…`) + non-canonical scalar → `InvalidKey` | 1 | B | — | M-A3 |
| A3-2 | `pub(crate)` widening of `key_cli`/`key_cmd` shared items (ceremony/mnemonic/passphrase reuse-in-place) — visibility-only | 1 | B | — | M-A3 |
| A3-3 | `account_cli` + `AccountConfig` — clap namespace, TTY guard, `--count`/`--output-dir`/`--start-index`, three-form `--mnemonic-passphrase`, `main` dispatch | 2 | A | A3-2 | M-A3 |
| A3-4 | `account_cmd` — `AccountDeps` seam + `account new` derive→address→encrypt→filename→write pipeline, ceremony, SIGINT, EIP-55 summary (six-way fan-in) | 2 | A | A3-3, A3-1, A3-2, A1-2, A2-1, A2-2 | M-A3 |
| A3-5 | exit-map (`AppError::Bip32 => 3`, call-site `Exit{3}` for write) + `account new` secret-hygiene test (reuse BLS `no_secret_in_logs`) | 1 | A | A3-4 | M-A3 |
| A4-1 | `account recover` — TTY-or-piped-stdin mnemonic (no ceremony), `validate_mnemonic` first (1-based bad word), `--start-index`/`--count` range, reuse pipeline, **recover-stdin hygiene** | 2 | A | A3-4 | M-A4 |
| A4-2 | three-form mnemonic passphrase across **both** commands (confirm-new vs single-entry-recover) + empty default + seed-derivation anchor test | 1 | A | A4-1 | M-A4 |
| A5-1 | in-binary E2E — fixed mnemonic → `account recover` → v3 keystores (0600/filename/address), **cross-recovery** (one seed → BLS + EOA trees) | 2 | A | A4-2 | M-A5 |
| A5-2 | docs — USER-GUIDE `account` section, README, CHANGELOG (raw-passphrase `ps`/history note; v3 raw-passphrase C-4 rule) | 1 | B | A5-1 | M-A5 |
| A5-M | **combined H9 + C-2** manual cross-tool parity session — `cast`/geth/MetaMask unlock + address parity (EOA) **and** ethstaker-deposit-cli pubkey parity + client import (BLS), one sitting, both logs | — | manual | A5-1 | M-A5 |

**Total: 21 points** (≈ 10.5 person-days single-dev) across 13 pointed issues + 1 unpointed manual
session. Critical path ≈ 14 pts (stream A: A1 → A3-3/A3-4/A3-5 → A4 → A5-1); stream B's ~7 pts (A2=4,
`secret_to_address`=1, widening=1, docs=1) overlap and join at A3-4.

## Execution order (2 parallel streams)

Phase numbers are **thematic**; the `Depends on` column drives order. The A/B split from the project
plan is real — no stream-B issue secretly depends on stream A except at the A3-4 join.

**Stream A (critical path, ~14 pts):**
`A1-1 → A1-2 → A3-3 → A3-4 → A3-5 → A4-1 → A4-2 → A5-1` → then the combined manual session **A5-M**.
(A3-3 needs only A3-2 from stream B, so it overlaps A1 on the schedule; A3-4 is the fan-in.)

**Stream B (parallel, ~7 pts, joins at A3-4):**
`A2-1 → A2-2` (v3 writer) · `A3-1` (`secret_to_address`) · **`A3-2` first** (widening — visibility-only,
unblocks stream A's A3-3, land it early on `develop`) · `A5-2` (docs, after A5-1).

**Effective order:** `A3-2` (unblock) + `A1` ∥ `A2` ∥ `A3-1` → `A3-3` → **`A3-4` (join)** → `A3-5` →
`A4-1 → A4-2` → `A5-1` → `A5-2` ∥ **`A5-M`**.

## Milestone gates

| Milestone | Issues | Exit criterion |
|---|---|---|
| M-A1 | A1-1, A1-2 (+ A3-1 for the address half) | BIP-32 TV1 (keys + chain codes) + Ethereum BIP-44 **secrets** (`1ab42cc4…`/`9a983cb3…` vs `cast`) green; `k256` `zeroize`-feature decision recorded (R1). The EIP-55 **addresses** (`0x9858…`/`0x6Fac…`) are gated by **A3-1** — see Gaps #2 |
| M-A2 | A2-1, A2-2 | G3 byte-gate reproduces the `cast` fixture (`ciphertext a5ae5118…`/`mac 8163019b…`) byte-for-byte at `n=8192`; **non-ASCII raw-passphrase guard** green (C-4); self round-trip; `len!=32` → exit 3; `v3_filename` fixed vector |
| M-A3 | A3-1..A3-5 | `account new` green — non-TTY → exit 2, display + full re-entry (mismatch → exit 4, nothing on disk), `--count N` writes N v3 files at `0600` with parsing `UTC--` names + EIP-55 summary; `secret_to_address` vectors; secret-hygiene test green |
| M-A4 | A4-1, A4-2 | `account recover` TTY/piped-stdin (no ceremony), `validate_mnemonic` first (12–24 words, 1-based bad word → exit 2), `--start-index`/`--count` range; three-form mnemonic passphrase on both commands + seed anchor |
| M-A5 (final) | A5-1, A5-2, A5-M | E2E fixture frozen (0600/filename/address) + cross-recovery shown; docs done; **A5-M combined parity session recorded** with pinned versions (EOA `cast`/geth/MetaMask + BLS ethstaker) — any mismatch blocks release |

## Conventions (all issues)

- Per-issue commits tagged `[A#-#]` on `develop`; **fast-forward** merges; every merge green
  (`make test && make lint`).
- Every acceptance criterion is executable/checkable and cites the requirement ID(s) it satisfies plus
  the concrete vector/fixture. Long hex lives in [`../research/`](../research/); issues cite the doc +
  section and inline only the short anchors (`5eb00bbd…` empty-passphrase seed, `a5ae5118…`/`8163019b…`
  v3 fixture, `0x9858…Eda94` address).
- Secret-hygiene tests (S-1/S-2) are explicit criteria on the leak-surface issues: **A1-1** (scalar
  /chain-code zeroize + R1 decision), **A2-1** (secret never serialized), **A3-5** (`account new`
  ceremony/banner + full hygiene harness), **A4-1** (recover-stdin surface).
- Paths are repo-root-relative (`crates/ethernal-core/src/…`, `bins/ethernal/src/…`), matching the
  architecture doc and the actual layout.

## Gaps & sizing notes flagged during estimation

**No deviation from the plan's totals.** The project-plan Stage-6 guide sizes A1=4, A2=4, A3=7, A4=3,
A5=3 (+manual) = **21 pts / ~13 issues + 1 manual**; this cut reproduces each per-phase total exactly
(A1 3+1, A2 3+1, A3 1+1+2+2+1, A4 2+1, A5 2+1+manual) with **13 pointed issues + 1 manual session**. No
issue was added, merged, split beyond the plan's guide, or re-pointed. The following were surfaced
while detailing them:

1. **C-4 needs its own guard — the ASCII byte-gate can't catch a wrong `normalize_passphrase` call.**
   The G3 fixture password `testpassword` is NFKD-stable, so the byte-gate passes whether or not
   `encrypt_v3` wrongly normalizes. A2-1 therefore carries a **separate** acceptance criterion: a
   non-ASCII / NFKD-unstable passphrase must derive its `dk` from **raw** UTF-8 bytes and differ from
   `normalize_passphrase` output. This is the automated guard for the R2 release-gate trap; without it,
   the most import-breaking bug (`web3-v3-keystore.md` §"the passphrase-normalization trap") would ship
   green. No point change.

2. **M-A1's "EIP-55 addresses matching cast" clause is delivered by A3-1 (signer), not A1 (core).**
   `core` has `k256`+`hmac`+`sha2` but **no keccak** (architecture Design note (b) keeps keccak solely
   in `signer`), so `core::hd_secp256k1` cannot compute an Ethereum address. A1-2 gates the BIP-44
   **secrets** (`1ab42cc4…`/`9a983cb3…` vs `cast wallet private-key`); the **addresses** (`0x9858…`/
   `0x6Fac…`) are gated in **A3-1**'s `secret_to_address` test using those same secrets. A3-1 is stream
   B / deps `—`, so it lands alongside A1 and M-A1 still closes on time — the two issues together close
   the full `abandon` clause. This is a milestone/issue-boundary clarification, not an added issue.

3. **A4-2 is deliberately test-heavy (F-12 completeness), not new plumbing.** The three-form
   `--mnemonic-passphrase` logic is **reused verbatim** from keygen (`MnemonicPassphraseForm` +
   `resolve_mnemonic_passphrase`, widened in A3-2, already unit-tested on the BLS side). A3-4 fully
   honors it for `account new` and A4-1 for `account recover` — **neither stubs it** (guarding the
   parse-but-ignore trap). A4-2 is the consolidated cross-command F-12 issue (three forms × both
   commands, confirm-new vs single-entry-recover, empty default, seed-derivation anchor). Kept as a
   distinct issue per the plan's A4 = 2-issue cut, which the phase total depends on; its 1 pt is mostly
   tests.

4. **A5-1's cross-recovery is a structural demo with a one-sided external anchor.** No single
   mnemonic+passphrase has published vectors for **both** trees: `abandon`+**empty** → seed `5eb00bbd…`
   → EOA addresses cast-verified, but the BLS EIP-2333 case-0 vector is `abandon`+**TREZOR** →
   `c55257c3…`. So A5-1 anchors the **EOA** half to the cast address vector (empty passphrase) and
   **regression-locks** the BLS pubkeys from that same seed (no external-vector claim). The BLS half
   reuses the already-merged `core::hd` (no A-issue dependency). The both-trees-**external** cross-check
   is A5-M against ethstaker-deposit-cli. This is honesty about which half is vector-anchored, not a
   scope change.

5. **A3-4 is at the 2-pt weight with a six-way fan-in** (A3-3, A3-1, A3-2, A1-2, A2-1, A2-2). Kept
   intact per the plan (A3 was already split into helper/widening/CLI/pipeline/hygiene). Called out so
   schedulers treat it as the integration bottleneck — it cannot start until both primitive streams
   (A1, A2) and the signer helper/widening land.

6. **A3-2 (widening) should land FIRST in stream B.** It is visibility-only, near-zero-risk (H1–H8
   merged → no in-flight H-code on `key_cli`/`key_cmd`, R5), and it unblocks stream A's A3-3. Scheduling
   it early maximizes the A/B overlap; its regression gate is simply the existing BLS `key` suite
   staying green.

7. **`keystore` reuse needs no new visibility (refines the research map).** `crypto::derive_scrypt`,
   `crypto::Aes128Ctr`, and `encrypt::format_uuid_v4` are already `pub(crate)`; `encrypt_v3` is
   in-crate, so A2-1 calls them directly — the existing-code-map note that said "make pub" is
   superseded by the architecture (§"`keystore` reuse"). Only `signer::secret_to_address` is a **new
   `pub` export** (A3-1); the `key_cli`/`key_cmd` widening (A3-2) is `pub(crate)` within the bin.

---

*Filename note: the sibling `docs/plan/keygen/issues/` uses `index.md` as its summary file; this file
mirrors that name/format. The Stage-6 brief called it `summary.md` — rename if the pipeline expects
that exact name (content is identical either way).*
