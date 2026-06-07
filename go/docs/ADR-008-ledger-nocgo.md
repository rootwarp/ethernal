# ADR-008: Delete `ledger_nocgo.go` stub and unreachable `ErrLedgerNotSupported` path

- **Status:** Accepted (M2.3; closes FR-P2-A4 / GO-050 / Spike S4)
- **Date:** 2026-06-07
- **Context:** Per GO-050 (adversarial review), `internal/signer/ledger_nocgo.go` (`//go:build !cgo`) can never compile or be reached: the signer package transitively imports `internal/tx` → `internal/deposit` → `internal/bls` → herumi/bls-eth-go-binary (CGO-only). The module requires `CGO_ENABLED=1` for all builds (PRD §7.5, architecture §6.9, Makefile). The stub's `newLedgerHub` init returning `ErrLedgerNotSupported` and the sentinel itself (defined in errors.go) were dead/unreachable, yet documented in godoc, package comments, exit-code tables, and test contracts. This gave a false promise of CGO-optional Ledger support (while usbwallet also needs CGO). Project-plan Spike S4 and m2.3-convention-architecture.md Issue M2.3-2 called for the decision (delete vs. break `signer→bls` cycle) recorded in ADR-008. Estimator default: "delete the stub" (1pt code change; bulk of 3pt is the write-up and audit).
- **Decision:** Delete the stub file, the sentinel, and all references to the unreachable path. Choose the simpler "delete" option. No CGO=0 CI matrix (the break-cycle alternative was scoped higher-cost per SUMMARY Open Scope Risk #3 and yields no practical benefit given herumi).
- **Rationale:** 
  - Matches estimator default and "minimal 1pt of code change".
  - Removes dead code and misleading build-tag claims (CONVENTIONS + hygiene theme of M2).
  - CGO requirement is already a hard fact for the module (BLS for both CLIs; Ledger transport secondary).
  - Preserves all existing behavior for supported (CGO) builds and Ledger E2E path.
  - ADR record + updates to architecture §6.9/§20 provide traceability without scope creep.
- **Alternatives considered:**
  - Break the `signer → bls` cycle (e.g. extract bls-free validation surface or move deposit/tx read-path deps) so `CGO_ENABLED=0 go build ./internal/signer` would succeed, then add CI matrix per AC. Rejected: ≥2pt refactor + 2pt CI per plan; still requires CGO for full `go build ./...`, for eth-deposit-gen (which uses bls directly), and for Ledger (usbwallet). Higher cost, no user-visible win.
  - Keep the stub "for hygiene." Rejected: it is unreachable and untested (never type-checked under CGO=1); violates "no dead code" hygiene.
- **Consequences:**
  - Files removed: `go/internal/signer/ledger_nocgo.go`.
  - Sentinel `signer.ErrLedgerNotSupported` deleted (and removed from errors.go, exit.go Is-chain, all contract/exit/sentinel tests, godoc, comments).
  - Package/func docs and transport comments updated to state CGO requirement explicitly (no more nocgo references).
  - Exit code 3 mapping and test contracts simplified (no unreachable case).
  - New ADR file: `go/docs/ADR-008-ledger-nocgo.md`; architecture.md §20 extended with entry and §6.9 M2 note updated.
  - No behavior change for CGO=1 builds/tests/Ledger flows (all ACs for delete satisfied; break-cycle ACs N/A).
  - CGO remains mandatory (documented); no false CGO-free claim remains (per PRD).
  - gofmt/make lint/CGO=1 builds+tests pass; CGO=0 still fails (on herumi, as before and expected).
- **Verification:** Audit (grep/read of all import sites, CGO guards, bls refs in signer subtree, Makefile, CI workflows, plan docs for GO-050/Spike S4); decision per default; smallest targeted edits only (no new features, no plan/issues/*.md); full verifs (gofmt, `make -C go lint`, CGO=1/0 builds, package+contract tests); AC checkboxes updated in review/summary text; Implementation Summary appended; relative paths; role/persona notes.
- **Related:** M2.3-2, architecture §6.9, PRD FR-P2-A4, REVIEW GO-050, project-plan Spike S4, ADR-001..007 precedent (simple bullet format).

(Recorded as part of M2.3-2 implementation per binding directive; "yes proceed and don't stop until completing every issues. additionally, update \"acceptance criterias\" checkboxes.")
