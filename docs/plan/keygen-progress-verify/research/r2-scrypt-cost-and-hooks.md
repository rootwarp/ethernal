# R2 — What the keygen loop actually spends time on, and whether scrypt can be instrumented

**Question.** Where does wall-clock go in `validator new --count N`, and can anything render
progress *inside* the expensive step?

---

## 1. Measured scrypt cost

`ScryptParams::STANDARD` = `n=262144 (log_n=18), r=8, p=1, dklen=32` — documented at
`crates/ethernal-keystore/src/encrypt.rs:108`, the EIP-2335 / staking-deposit-cli profile.

Measured directly against `scrypt` 0.11.0 (the exact workspace dependency, from the local
registry) with those parameters, `--release`:

```
first: 355.3 ms    (cold)
run1:  311.5 ms
run2:  308.7 ms
run3:  310.4 ms
```

Machine: this development host (Apple Silicon). **≈ 310 ms per scrypt call.** The 128 MiB
working set (`128 · r · n` = 256 MiB peak counting the two buffers) means the figure is
memory-bandwidth-bound and degrades on older server hardware — a bastion or air-gapped box is
realistically **2–4×** slower. Treat 310 ms as the floor, ~1.2 s as a plausible ceiling per
scrypt on target deployment hardware.

The workspace already knows scrypt is the hot spot: root `Cargo.toml` carries

```toml
[profile.dev.package.scrypt]
opt-level = 3
```

landed as issue **E1-1** of the e2e-tests plan, which measured **~19–20 s per keystore**
unoptimized versus **~0.6 s** optimized (`docs/plan/e2e-tests/issues/e1.md` on `main`). That
~0.6 s figure is a two-keystore *end-to-end test* including process startup and I/O; it is
consistent with the ~310 ms pure-KDF number here.

## 2. Cost of everything else in the loop

Per index (`validator_cmd.rs:313`–`375`):

| Step | Work | Order |
|---|---|---|
| `hd::derive_path` | EIP-2333 tree walk, ~4 HKDF-based child derivations | µs |
| entropy draws | 32 + 16 + 16 bytes from the OS CSPRNG | µs (but *can block* on a starved air-gapped host) |
| `encrypt` | **scrypt** + AES-128-CTR + SHA-256 | **~310 ms** |
| `write_keystore_at` | one `create_new` 0600 write | ms |
| C1/C2 (proposed) | `sk_to_pk` + `key_validate` | µs |
| C3 (proposed) | one BLS sign + one verify | ~1–2 ms |
| C4 (proposed) | file read + **scrypt** + AES + SHA-256 compare | **~310 ms** |

Outside the loop, once: `bip39::to_seed` (PBKDF2-HMAC-SHA512, 2048 iterations) — single-digit
ms, not worth a phase.

**Conclusion:** the loop is ~99% scrypt today and will be ~99% *two* scrypts after C4. Any
progress design is really a design about what to show around two opaque 310 ms blocks.

## 3. Can scrypt itself be instrumented?

**No.** The crate's entire public surface (`~/.cargo/registry/.../scrypt-0.11.0/src/`):

- `scrypt::scrypt(password, salt, params, output) -> Result<(), InvalidOutputLen>`
  (`lib.rs:89`) — one blocking call, no callback, no iterator, no cancellation token.
- `Params::new / recommended / log_n / r / p` (`params.rs`) — parameters only.

There is no progress hook to grab. Two theoretical decompositions, both dead ends:

- **Split by `p`.** scrypt's `p` parallelism factor would let the KDF be run in `p`
  independently-schedulable chunks. EIP-2335 fixes **`p = 1`**. Nothing to split.
- **Reimplement ROMix with a callback.** Rewriting the KDF inner loop to report progress
  means hand-rolling a cryptographic primitive to draw a nicer bar. Categorically rejected for
  a key-generation tool.

Therefore anything rendered *during* a single scrypt must come from **another thread**, which
is a seam change, not a rendering change — see
[`r1-progress-rendering.md`](r1-progress-rendering.md) §3.

## 4. What this means for the design

1. A "bar" whose only unit is completed keys is nearly useless at `--count 1` (the dominant
   interactive case) — it renders `1/1` once, at the end.
2. Phase-boundary reporting bounds the silent interval at **one scrypt** (~310 ms here,
   ~1.2 s worst realistic case) regardless of `N`. That satisfies PR-2 without a thread.
3. Verification must be modelled *in* the indicator: C4 is a second scrypt, so a bar that
   treats "written" as done is wrong by a factor of two.

**Connections:** [`r1-progress-rendering.md`](r1-progress-rendering.md) ·
[`r3-verification-semantics.md`](r3-verification-semantics.md) ·
`docs/plan/e2e-tests/issues/e1.md` (on `main`, the prior scrypt measurement)
