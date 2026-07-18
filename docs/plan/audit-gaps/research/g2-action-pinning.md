# Research: G2 — Pin GitHub Actions to full commit SHAs (ETHSTAKER-1)

## Verdict
Pin all three third-party actions to the full 40-char **commit** SHA they currently resolve to
(deref annotated tags), with a version comment. Resolved values below. Confidence **High** — each
SHA cross-checked against two GitHub API surfaces (+ the releases page for `actions/checkout`). Two
non-obvious traps found: (a) **`dtolnay/rust-toolchain@stable` is a *branch*, not a tag** — the
version comment cannot be a semver; (b) **`Swatinem/rust-cache@v2` resolves to a changelog commit one
past the `v2.9.1` release tag**, so the "obvious" v2.9.1 pin is *not* what `@v2` currently gives.

## Resolved pins (resolved 2026-07-18; **re-verify verbatim before commit** — see commands below)

| Action | Current ref | Ref type | Tag-object SHA | **Commit SHA → goes in `ci.yml`** | Comment |
|---|---|---|---|---|---|
| `actions/checkout` | `@v4` | lightweight tag (ref → commit) | n/a (ref points straight to commit) | `34e114876b0b11c390a56381ad16ebd13914f8d5` | `# v4.3.1` |
| `dtolnay/rust-toolchain` | `@stable` | **branch** (not a tag) | n/a | `4cda84d5c5c54efe2404f9d843567869ab1699d4` | `# stable branch @ 2026-07-16` |
| `Swatinem/rust-cache` | `@v2` | **annotated** tag | `42dc69e1aa15d09112580998cf2ef0119e2e91ae` | `e18b497796c12c097a38f9edb9d0641fb99eee32` | `# v2 (tip ≈ v2.9.1, 2026-03-12)` |

Resulting `ci.yml` lines:

```yaml
- name: Checkout
  uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1

- name: Set up Rust
  uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable branch @ 2026-07-16
  with:
    toolchain: stable
    components: clippy, rustfmt

- name: Cache cargo
  uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2 (tip ≈ v2.9.1, 2026-03-12)
```

(The existing `with: { components: clippy, rustfmt }` block on `rust-toolchain` stays; only add
`toolchain: stable` above it. `checkout` and `rust-cache` take no `with:` today — unchanged.)

## Best practice for SHA pinning (current, 2026)
- **Pin to the full 40-hex commit SHA, not an abbreviation and not a tag.** A tag is mutable — a
  compromised or coerced maintainer can retag `v4`/`v2` to a malicious commit; a 40-char commit SHA
  is immutable. This is the GitHub-hardening / OpenSSF Scorecard `Pinned-Dependencies` /
  SLSA recommendation [1][2]. Abbreviated SHAs are rejected by some tooling and are theoretically
  ambiguous.
- **Deref annotated tags to the commit.** `git ls-remote <repo> v2` prints the *tag-object* SHA for
  an annotated tag; `git ls-remote <repo> 'v2^{}'` (or the API `/commits/v2`) prints the
  **dereferenced commit** SHA. The commit SHA is what a `uses:` must reference — GitHub resolves a
  `uses:` SHA as a commit. Pinning the tag-object SHA of an annotated tag will fail to check out.
  This is exactly the `rust-cache` case below. [3]
- **Trailing version comment** (`# v4.3.1`) for human readability and so update tooling can map the
  pin back to a version.
- **Keep pins fresh with automation.** Dependabot (`package-ecosystem: github-actions`) and Renovate
  both understand SHA-pinned actions with version comments: they bump the SHA *and* the comment on
  new releases, preserving the pin. Add/confirm a Dependabot config when the release pipeline (gap 5)
  lands so pins don't rot. [1][4]

## Per-action detail

### `actions/checkout@v4`
- `GET /repos/actions/checkout/git/refs/tags/v4` → `object.type = "commit"`, so `v4` is a
  **lightweight** moving tag pointing directly at a commit: `34e114876b0b11c390a56381ad16ebd13914f8d5`.
  No deref needed (tag SHA == commit SHA).
- Cross-check: `GET /commits/v4` → same SHA; the **releases page** shows release **v4.3.1** (published
  2025-11-17, "Port v6 cleanup to v4", PR #2305) targeting the identical full SHA. Three surfaces
  agree → high confidence.
- The latest *overall* release is v7.0.0; pinning `@v4`'s current commit keeps the major line
  unchanged (satisfies G2-3 "no version upgrade").

### `dtolnay/rust-toolchain@stable` — the branch-not-tag trap
- `GET /repos/dtolnay/rust-toolchain/tags` returns a single tag: `v1`. There is **no `stable` tag and
  no v2+ semver tags** — `stable`, `nightly`, `1.89.0`, etc. are **branches**. `@stable` checks out
  the `stable` branch's tip. [5]
- Current `stable` branch tip: `4cda84d5c5c54efe2404f9d843567869ab1699d4` (commit
  "toolchain: stable", 2026-07-16 — the branch is force-updated frequently).
- **Version comment cannot be a semver** (there is no version). Use the branch name + commit date:
  `# stable branch @ 2026-07-16`. Do **not** fabricate a `# v1.x.y`.
- **Interaction with the branch-name-as-toolchain convention:** the action selects the toolchain from
  its `@rev` by convention (`@stable` → stable, `@1.89.0` → 1.89.0) [6]. When you replace `@stable`
  with a bare `@<sha>`, the ref no longer *names* a toolchain, so selection falls to the action's
  `inputs.toolchain` default **at that commit**. I confirmed `action.yml` on the `stable` branch has
  `inputs.toolchain.default: stable` [7] — so pinning the stable-branch tip is self-consistent. Still
  set `with: toolchain: stable` **explicitly** (per G2-2): it makes selection deterministic and
  independent of which branch's `action.yml` the SHA happens to carry (a future re-pin to a shared or
  `master` commit could default differently). This is the community-standard pattern; note the
  `dtolnay/rust-toolchain` README does **not** ship an explicit `@<sha>` + `toolchain:` example [6],
  so cite G2-2's rationale, not the README.

### `Swatinem/rust-cache@v2` — the annotated-tag + moved-major trap
- `GET /git/refs/tags/v2` → `object.type = "tag"` (annotated); tag-object SHA
  `42dc69e1aa15d09112580998cf2ef0119e2e91ae`.
- Dereferenced commit (`GET /commits/v2`): `e18b497796c12c097a38f9edb9d0641fb99eee32`
  (2026-03-12T17:15:39Z, "update changelog…"). **This is the pin.**
- **Trap:** the latest `v2.x.y` release is **v2.9.1** = commit
  `c19371144df3bb44fab255c43d04cbc2ab54d1c4` (2026-03-12T17:15:22Z) — a *different* commit, 17s
  earlier. The maintainer left the moving `@v2` tag on the **changelog commit immediately after**
  the v2.9.1 release tag. So `@v2` today resolves to `e18b4977…`, **not** to the v2.9.1 release
  commit. Per G2-1/G2-3 ("the SHA the tag currently resolves to", "no upgrade"), pin `e18b4977…`.
  - *Co-equal alternative (implementer's call):* pin the actual **v2.9.1 release commit**
    `c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1`. The two commits differ only by a
    changelog/docs commit, so behavior is identical — and for an ETHSTAKER-1 *supply-chain* pin,
    anchoring to a **released, tagged** commit arguably has marginally better auditability than a
    "changelog-tip" commit that carries no release tag. Net: `e18b4977…` honors the literal "resolve
    what `@v2` currently gives" requirement (G2-1/G2-3); `c193711…` gives cleaner release provenance.
    Choose one deliberately, and **do not** silently assume `@v2` == v2.9.1 — it does not.

## Re-verify commands (put in the PR description; run before committing the pins)
```sh
# Deref'd commit SHAs (what goes in ci.yml):
gh api repos/actions/checkout/commits/v4            --jq .sha   # expect 34e11487…
gh api repos/dtolnay/rust-toolchain/commits/stable  --jq .sha   # expect 4cda84d5…  (moves often!)
gh api repos/Swatinem/rust-cache/commits/v2         --jq .sha   # expect e18b4977…

# Without gh — note the ^{} deref for the annotated rust-cache tag:
git ls-remote https://github.com/actions/checkout        v4
git ls-remote https://github.com/dtolnay/rust-toolchain  stable
git ls-remote https://github.com/Swatinem/rust-cache     v2        # tag-object 42dc69e1…
git ls-remote https://github.com/Swatinem/rust-cache     'v2^{}'   # deref'd commit e18b4977…
```
`dtolnay/rust-toolchain@stable` is a fast-moving branch — its SHA will very likely differ by commit
time; **resolve it fresh at implementation** and update the comment date. The checkout and rust-cache
tags are stable and unlikely to move.

## Implications for implementation
1. **These are the three pins; `dtolnay` needs the extra `with: toolchain: stable` line.** No other
   `ci.yml` change (`make lint`/`make test`/`make e2e-mock`/release-build steps untouched).
2. **Re-resolve `dtolnay/rust-toolchain@stable` at implementation time** — it is a branch tip and
   moves; my 2026-07-16 SHA may be stale by the time G2 is executed. checkout/rust-cache are safe to
   use as recorded but should still be spot-checked with the commands above.
3. **Comment style is not uniform:** semver for checkout (`# v4.3.1`), branch+date for dtolnay,
   tag-tip note for rust-cache. Do not force a `# vX.Y.Z` onto dtolnay.
4. **Validation:** `actionlint` will parse the pinned SHAs fine; there is no `actionlint` in the repo
   today, so a YAML parse + a green CI run is the acceptance evidence (G2-3). Confirm the CI log still
   shows the stable toolchain installed and clippy/rustfmt present.
5. This unblocks gap 5 (release/signing pipeline, disposition D1), which must start from pinned
   actions; wire Dependabot `github-actions` updates when that pipeline lands so the pins stay fresh.

## Sources
[1] [Security hardening for GitHub Actions — GitHub Docs](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions) — "Pin actions to a full length commit SHA"; Dependabot support. Official docs (general guidance; not re-fetched this session).
[2] [OpenSSF Scorecard — Pinned-Dependencies check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies) — rationale for full-SHA pinning. Reference.
[3] [GitHub REST API — Git refs / dereferencing annotated tags](https://docs.github.com/en/rest/git/refs) — `/commits/{ref}` and `^{}` deref semantics. Official docs. Verified live via `/repos/Swatinem/rust-cache/git/refs/tags/v2` (`object.type: tag`) vs `/commits/v2`.
[4] [Dependabot / Renovate SHA-pin bumping](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot) — keeps SHA pins + comments fresh. Official docs.
[5] `GET https://api.github.com/repos/dtolnay/rust-toolchain/tags` — live, 2026-07-18: single tag `v1`; confirms `stable` is a branch. Primary (GitHub API).
[6] [dtolnay/rust-toolchain README](https://github.com/dtolnay/rust-toolchain) — toolchain selected by `@rev`; no explicit `@<sha>` + `toolchain:` example. Primary (repo README), fetched live.
[7] `GET https://raw.githubusercontent.com/dtolnay/rust-toolchain/stable/action.yml` — live, 2026-07-18: `inputs.toolchain.default: stable`. Primary (repo source).
[8] Live GitHub API resolutions, 2026-07-18: `/commits/v4` = `34e114876b0b11c390a56381ad16ebd13914f8d5`; `/commits/stable` = `4cda84d5c5c54efe2404f9d843567869ab1699d4`; `/commits/v2` = `e18b497796c12c097a38f9edb9d0641fb99eee32`; `/commits/v2.9.1` = `c19371144df3bb44fab255c43d04cbc2ab54d1c4`; `actions/checkout` releases page → v4.3.1 targets `34e11487…`. Primary (GitHub API + releases page); resolved via WebFetch — re-verify with the commands above before commit.
