# Research — Sender-address (`--from`) flag prior art (supports PRD F1.3)

**Question:** when building an *unsigned* transaction, do ecosystem tools require an
explicit sender/`--from`, and how do they get the nonce? Does the PRD's rule match
convention?

## Finding: nonce auto-fetch fundamentally needs a known sender

The `from` address is not a field of a signed Ethereum transaction; it is recovered from
the signature. Tools only use it to **look up the next nonce** (`eth_getTransactionCount`)
and to estimate gas. So any tool that auto-fills the nonce for an *unsigned* tx must be
told who the sender is — there is nothing to recover it from yet. This is the exact
reason `resolveRPC` returns `ErrMissingFromForNonce` when `From` is zero and `Nonce` is
nil (`internal/tx/builder.go:128-129`).

## cast (Foundry) — `cast mktx --raw-unsigned`

- `cast mktx` has `--from` ("The sender account"), `--nonce` ("Nonce for the
  transaction"), and `--raw-unsigned` ("Generate a raw RLP-encoded unsigned transaction.
  **Relaxes the wallet requirement.**").
- With `--raw-unsigned`, the wallet requirement is relaxed, so **`--from` is not
  required** — you can build a fully unsigned tx without a signer present. When you *do*
  want the nonce filled from the node, you supply `--from` (or `--nonce` explicitly);
  with neither a wallet nor `--from`, there is no address to query the pending nonce for.
- This is the same shape as the PRD: sender is optional for building unsigned, but
  becomes necessary precisely when you ask the tool to resolve the nonce for you.

Sources: [cast mktx reference](https://getfoundry.sh/cast/reference/mktx/),
[Foundry Book — cast mktx](https://book.getfoundry.sh/reference/cli/cast/mktx).

## ethdo / ethereal (wealdtech) — offline model

The wealdtech offline workflow is: build the unsigned tx **online** where the account
state (current nonce, balance) can be retrieved, then transfer to the air-gapped device
to sign. The `from` address is "used to lookup the next nonce value to use when sending
from this address" — i.e., building offline (no node) means the nonce must be provided,
and the sender is what makes online nonce lookup possible.

Sources: [ethdo docs/usage.md](https://github.com/wealdtech/ethdo/blob/master/docs/usage.md),
[ethereum book ch.6 — Transactions](https://cypherpunks-core.github.io/ethereumbook/06transactions.html).

## Verdict: the PRD's rule matches ecosystem convention

| Mode | PRD rule | Matches convention? |
|---|---|---|
| `build`, `--rpc-url` given, `--nonce` omitted | `--from` **required** | Yes — sender is needed to fetch nonce (cast, ethdo) |
| `build`, `--nonce` supplied | `--from` **not required** | Yes — no lookup needed, sender is optional for unsigned |
| `run --signer local` | derive `From` from the held key | Yes — the wallet is present, so no flag needed (cast's non-`--raw-unsigned` path) |
| `run --signer ledger`, RPC mode | require `--nonce` (no offline address query) | Yes — no in-memory key; avoids touching the device early (N1) |

The design is idiomatic: an explicit sender is required exactly and only when the tool is
asked to resolve a nonce and cannot otherwise know the address.
