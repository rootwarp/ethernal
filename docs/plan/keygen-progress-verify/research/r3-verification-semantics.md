# R3 — What "verify a BLS key after creation" has to mean here

**Question.** Which checks are worth running, what does each one actually catch, what does
the reference implementation do, and what happens on failure?

---

## 1. What the codebase already provides

Everything needed is public API today; no crate work is required.

| Primitive | Location | Use |
|---|---|---|
| `bls::new_signer(&[u8]) -> BlsSigner` | `ethernal-core/src/bls.rs` | rebuild a signer from the 32-byte secret |
| `Signer::public_key() -> [u8;48]` | same | recompute the pubkey from the secret (C1) |
| `bls::validate_pubkey_bytes([u8;48])` | same | on-curve + subgroup + non-identity (C2) |
| `Signer::sign([u8;32]) -> [u8;96]` / `bls::default_verifier()` / `Verifier::verify` | same | signature round trip (C3); `verify` uses `key_validate` + `sig_groupcheck=true` |
| `KeyLoader::load(path, &dyn PassphraseSource) -> Key` | `ethernal-keystore/src/keystore.rs:66` | decrypt the **written file** (C4) |
| `Key { secret: Vec<u8>, pubkey_hex: String }`, zeroized on drop | `keystore.rs:27` | compare material, then let `Drop` scrub |
| `DerivedSk::to_bytes() -> Zeroizing<[u8;32]>` / `::public_key()` | `ethernal-core/src/hd.rs:65`,`:73` | the reference values to compare against |

The `deposit gen` path already wires the same idea: `Generator::new(signer, verifier, params)`
(`deposit.rs:164`) self-verifies each signature, and `DepositError::SelfVerifyFailed` maps to
exit 3 (`errors.rs:277`). **The precedent, the error class, and the exit code all exist** —
keygen just never adopted them.

## 2. The four checks, and what each one actually catches

### C1 — sk → pk consistency (µs)

`new_signer(sk_bytes)?.public_key()? == derived.public_key()`.

Catches: a wrong secret being handed to `encrypt` while the *correct* pubkey is written into
the JSON and printed in the summary. That failure mode is quiet and catastrophic — the
operator deposits 32 ETH against a pubkey whose key they do not have. Note the two values come
from different code paths today: the pubkey from `DerivedSk::public_key()` (blst `sk_to_pk` on
the live `SecretKey`) and the encrypted secret from `DerivedSk::to_bytes()` (serialized
scalar). C1 closes the loop by re-deserializing the *serialized* bytes — exactly the
round-trip that is currently assumed rather than checked.

### C2 — pubkey point validity (µs)

`validate_pubkey_bytes(pubkey)` — `blst::min_pk::PublicKey::key_validate`, which rejects
off-curve points, points outside the prime-order subgroup, and the identity.

Catches: memory corruption between derivation and serialization; also makes the
"never publish an identity/small-subgroup pubkey" property explicit rather than inherited from
blst's internals.

### C3 — sign/verify round trip (~1–2 ms)

Sign a fixed 32-byte probe root with the reconstructed signer, verify against the pubkey with
`bls::default_verifier()`.

Catches: anything C1/C2 miss in the signing path itself — a key that deserializes and produces
a pubkey but cannot produce a verifying signature. This is a proof-of-possession in the same
spirit as the deposit message signature, and it mirrors the core crate's stated constraint:
*"every BLS signature is re-verified immediately after signing"* (`ethernal-core/src/lib.rs:5`).

The probe root is **not persisted** and the signature is discarded. A fixed constant is
sufficient; per-key randomization buys nothing here because the adversary model is
"our own code or hardware is broken", not "an attacker chose the message". Domain-separate the
constant (e.g. the SHA-256 of an `ethernal`-specific ASCII tag) so the probe signature can
never be confused with a consensus-domain signature if it ever escaped.

### C4 — keystore decrypt round trip (~310 ms — a full second scrypt)

`KeyLoader::load(written_path, &in_memory_passphrase)`, then assert **both**:

- `key.secret == derived_sk_bytes`
- `key.pubkey_hex == hex(derived_pubkey)`

Catches: truncated or partially-flushed writes; a filesystem that acknowledged a write it did
not persist; ciphertext corruption; a wrong-passphrase path; and the **pubkey/secret mismatch
in the JSON itself**.

That last one deserves emphasis. `KeyLoader` documents that it *does not* validate the JSON
`pubkey` field against the decrypted secret (`keystore.rs:29`), and `deposit gen` indexes
keystores by that field (`scan_dir` → `DirectoryIndex`, no decryption). So a keystore whose
`pubkey` field disagrees with its ciphertext is accepted by every later stage of this tool's
own pipeline. C4 comparing *both* fields is what makes that unrepresentable at the point of
creation.

**Cost note:** C4 is the entire cost of this feature. C1–C3 are free; C4 doubles per-key
wall-clock ([`r2`](r2-scrypt-cost-and-hooks.md) §1). This asymmetry is why C1–C3 are
mandatory and only C4 is behind `--no-verify`.

## 3. What the reference implementations do

From the vault's own survey and audit (authoritative for this project):

- **`staking-deposit-cli` / `ethstaker-deposit-cli` always verify** the keystore after
  creation — decrypt-back is not optional there.
- ethernal's audit records this as an explicit, still-open **deliberate deviation**:
  *"Runtime post-write decrypt verify optional / test-heavy (deposit-cli always verifies)"* —
  `1.Projects/ethernal/0.README.md` § "Deliberate deviations"; issue-by-issue detail in
  `1.Projects/ethernal/202607181903 - Audit - ethernal Implementation vs Known deposit-cli and EOA Keystore Issues.md`
  and the threat model in
  `202607181439 - Research - Known Security Issues in deposit-cli and EOA Keystore Creation`.

So C4 is not a novel idea to justify — it is closing a known, documented gap against the
reference implementation. What ethernal adds over deposit-cli is C1–C3 (deposit-cli's
verification is the decrypt round trip; it does not separately prove sk→pk consistency at
creation time) and the explicit `pubkey`-field comparison.

## 4. Failure semantics — the decision that needs stating

Three options for a failed C4, with the file already on disk at 0600:

| Option | Argument for | Argument against |
|---|---|---|
| **(a) Leave the file, hard error, exit 3** | Preserves evidence for diagnosis; consistent with the never-overwrite/`create_new`-exclusive write discipline; the operator, not the tool, decides what to do with a suspect artifact | A bad file sits in the output dir; a careless operator could use it |
| (b) Unlink the file | Nothing unusable is left behind | The tool deletes key material based on its own possibly-buggy check; a transient FS/read error destroys a keystore that was fine; deletion is the one irreversible act in a pipeline explicitly designed never to overwrite |
| (c) Rename to `*.invalid` | Quarantines without deleting | Adds a second filename convention and a second failure mode (rename fails); the operator still has to reason about it |

**(a).** The counter-argument to (a) is answered by the error message: it must name the exact
path, state that the file was **not** removed, and say it must not be used. Combined with
"stop the run immediately", the operator lands in a well-defined state — *k* verified
keystores plus one named suspect — rather than a directory they must audit by hand.

**Exit code 3**, per `main.rs:8` ("signer / crypto error"). Note the plumbing detail: routing
this through `AppError::Keystore(KeystoreError::…)` would yield **exit 2** for most variants
(`errors.rs:260`) and `AppError::Bls(_)` falls through to the fallback **1** (`errors.rs:74`).
Neither is right — the architecture specifies a typed variant with its own arm, following
`DepositError::SelfVerifyFailed`.

## 5. Passphrase handling for C4

`KeyLoader::load` needs a `&dyn PassphraseSource`. The keystore passphrase is already in scope
as `Zeroizing<Vec<u8>>` (`validator_cmd.rs:303`). Re-prompting or re-reading the env var per
key is unacceptable (interactive re-entry mid-loop; `EnvSource` re-read is a needless second
exposure). So the implementation needs a small in-process source that hands back a copy.

Constraint from the trait's own docs: `PassphraseSource::read` returns a **plain `Vec`** and
"the loader wraps the buffer in `Zeroizing` immediately… **Other callers must do the same** —
forgetting to re-wrap is a secret-residue footgun" (`passphrase.rs:27`). `Loader::load` is the
caller here and does wrap it, but the `Vec` produced by our source is one more copy of the
passphrase per key — it must be a fresh allocation the loader consumes, and the source itself
must hold its master copy in `Zeroizing`. The existing test-only `FixedPassphrase`
(`test_support.rs`) is the shape; this needs a production sibling.

**Connections:** [`r2-scrypt-cost-and-hooks.md`](r2-scrypt-cost-and-hooks.md) ·
[`../architecture.md`](../architecture.md) (D-4, D-5, D-6) ·
`1.Projects/ethernal/202607181903 - Audit - ethernal Implementation vs Known deposit-cli and EOA Keystore Issues.md`
