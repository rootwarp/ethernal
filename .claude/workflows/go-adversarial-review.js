export const meta = {
  name: 'go-adversarial-review',
  description: 'Adversarial multi-agent review of go/: code quality, security audit, potential bugs',
  phases: [
    { title: 'Find', detail: 'package-unit × dimension finders + tooling/deps/cross-cutting sweeps' },
    { title: 'Verify', detail: 'adversarial refuters per finding (3-vote panel for high/critical)' },
    { title: 'Critic', detail: 'completeness critic + follow-up finder round' },
    { title: 'Report', detail: 'synthesize go/plan/REVIEW.md' },
  ],
}

const ROOT = '/Users/nil-00/git/rootwarp/eth-utils/go'

const CONTEXT = `Project root: ${ROOT}
This is SECURITY-CRITICAL software: an Ethereum validator toolchain.
- cmd/eth-deposit-gen: generates validator BLS keys + deposit data (EIP-2335 keystores, SSZ hash tree roots, BLS signatures over DepositMessage).
- cmd/eth-deposit-tx: builds, signs (local keystore or Ledger hardware wallet) and broadcasts deposit transactions to the beacon deposit contract, including on mainnet where mistakes mean irreversible loss of 32+ ETH.
- internal/: bls, ssz, deposit, keystore, signer (local + ledger), tx (builder/rpc/validation/abi), cli, network, output.
Read ${ROOT}/CLAUDE.md and ${ROOT}/CONVENTIONS.md first for project conventions.`

const UNITS = [
  { key: 'gen', desc: 'cmd/eth-deposit-gen — deposit data generator CLI', files: `${ROOT}/cmd/eth-deposit-gen/main.go and main_test.go` },
  { key: 'tx-core', desc: 'cmd/eth-deposit-tx core flow — entrypoint, config, run', files: `${ROOT}/cmd/eth-deposit-tx/{main.go, config.go, run.go} plus their _test.go files` },
  { key: 'tx-ops', desc: 'cmd/eth-deposit-tx operations — send, sign, exit subcommands', files: `${ROOT}/cmd/eth-deposit-tx/{send.go, sign.go, exit.go} plus send_test.go, sign_test.go, exit_test.go, deposit_e2e_test.go, golden_test.go, signed_golden_test.go` },
  { key: 'signer', desc: 'internal/signer — local private-key and Ledger hardware-wallet signing', files: `all files in ${ROOT}/internal/signer/ (signer.go, local.go, ledger.go, ledger_cgo.go, ledger_nocgo.go, ledger_transport.go, parse.go, types.go, errors.go + tests)` },
  { key: 'keystore', desc: 'internal/keystore — EIP-2335 keystore load/scan + passphrase handling', files: `all files in ${ROOT}/internal/keystore/ (keystore.go, scandir.go, passphrase.go + tests)` },
  { key: 'crypto', desc: 'internal/bls + internal/ssz — BLS signatures and SSZ serialization/hash-tree-root', files: `all files in ${ROOT}/internal/bls/ and ${ROOT}/internal/ssz/ (including fuzz tests)` },
  { key: 'deposit-out', desc: 'internal/deposit + internal/output — deposit data model/JSON + output formatting', files: `all files in ${ROOT}/internal/deposit/ and ${ROOT}/internal/output/` },
  { key: 'tx-lib', desc: 'internal/tx — transaction builder, RPC client, validation, ABI encoding', files: `all files in ${ROOT}/internal/tx/ (builder.go, rpc_client.go, validation.go, abi.go, types.go, interface.go, errors.go + tests)` },
  { key: 'cli-net', desc: 'internal/cli + internal/network — CLI parsing and network parameters (chain ids, fork versions, contract addresses)', files: `all files in ${ROOT}/internal/cli/ and ${ROOT}/internal/network/` },
]

const DIMENSIONS = [
  { key: 'bugs', name: 'bug-hunting', prompt: `DIMENSION — POTENTIAL BUGS. Hunt for: logic errors; off-by-one; nil dereferences; swallowed, shadowed, or ignored errors; incorrect error wrapping that breaks errors.Is/As; race conditions and unsynchronized shared state; resource leaks (file handles, HID devices, RPC connections, goroutines); wrong edge-case handling (empty input, zero values, max values, duplicate entries); integer overflow/truncation (uint64→int, gwei↔wei conversions); endianness and serialization mistakes; incorrect amount/unit arithmetic; broken cleanup/defer ordering; context misuse (ignored cancellation, missing timeouts); slice aliasing/mutation bugs; map iteration-order dependence.` },
  { key: 'security', name: 'security audit', prompt: `DIMENSION — SECURITY AUDIT. Hunt for: private-key/seed/passphrase material left un-zeroized, copied, logged, echoed, or embedded in error messages; secrets written to files with loose permissions or to stdout when not intended; insufficient validation at trust boundaries (RPC responses, JSON files, environment variables, CLI flags, Ledger APDU responses); path traversal in file scanning; weak randomness or crypto misuse (BLS domain separation, signing the wrong root, missing fork-version binding); cross-network replay hazards (wrong chain-id, wrong fork version, wrong deposit contract address); TOCTOU on files; ways to bypass mainnet-safety confirmations; injection via untrusted strings; supply-chain-relevant misuse of dependencies; sensitive data in temp files or test fixtures.` },
  { key: 'quality', name: 'code quality', prompt: `DIMENSION — CODE QUALITY. Assess against ${ROOT}/CONVENTIONS.md and idiomatic Go: API design and package boundaries; duplication; dead code; needless complexity; naming; doc comments on exported identifiers; error-message and error-wrapping consistency; testability and meaningful test coverage of critical paths (weak coverage of a critical path may be reported, severity low); magic numbers that should be named constants; inconsistent patterns between sibling packages. Quality findings are usually severity low/info unless they create real operational risk. Do not pad — only report things a strong Go reviewer would actually flag.` },
]

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string', description: 'short specific title' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          category: { type: 'string', enum: ['bug', 'security', 'quality'] },
          file: { type: 'string', description: 'path relative to go/ e.g. internal/tx/builder.go' },
          line: { type: 'string', description: 'line number or range' },
          description: { type: 'string', description: 'what is wrong and why it matters' },
          evidence: { type: 'string', description: 'quoted code snippet proving the claim' },
          recommendation: { type: 'string' },
        },
        required: ['title', 'severity', 'category', 'file', 'line', 'description', 'evidence', 'recommendation'],
      },
    },
    summary: { type: 'string', description: 'one-paragraph overall assessment of the reviewed scope' },
  },
  required: ['findings', 'summary'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    isReal: { type: 'boolean' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    reasoning: { type: 'string', description: 'concise evidence-based justification' },
    adjustedSeverity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info', 'unchanged'] },
  },
  required: ['isReal', 'confidence', 'reasoning', 'adjustedSeverity'],
}

const CRITIC_SCHEMA = {
  type: 'object',
  properties: {
    assessment: { type: 'string' },
    gaps: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          instruction: { type: 'string', description: 'self-contained investigation instruction for a follow-up agent' },
        },
        required: ['title', 'instruction'],
      },
    },
  },
  required: ['assessment', 'gaps'],
}

const FINDER_RULES = `Rules:
- Read EVERY file in your scope completely. Follow call paths into other packages when needed to confirm behavior — never guess.
- Report ONLY concrete findings supported by specific code evidence (file + line + quoted snippet).
- No speculative issues, no issues purely inside third-party dependencies (only their misuse by this code).
- In test files, only flag tests that are themselves wrong or misleading (assert the wrong thing, mask failures), not coverage wishes — except as allowed by your dimension instructions.
- Maximum 10 findings; pick the most important. An empty findings list is a valid answer.
- Severity scale: critical = key compromise or irreversible funds loss; high = wrong on-chain data, serious vulnerability, or data corruption; medium = real bug/vulnerability with limited impact; low = minor bug or risk; info = noteworthy observation.
- Your final message is consumed by a program, not a human.`

function unitPrompt(unit, dim) {
  return `You are an expert Go reviewer performing an adversarial ${dim.name} review.

${CONTEXT}

YOUR SCOPE: ${unit.desc}
Files: ${unit.files}

${dim.prompt}

${FINDER_RULES}`
}

const SPECIALS = [
  {
    key: 'tooling',
    prompt: `You are running automated analysis tooling over the Go module at ${ROOT}.

${CONTEXT}

Run from ${ROOT} (use the Bash tool):
1. go build ./...
2. go vet ./...
3. gofmt -l .
4. go test ./... -count=1  — first check test/e2e and any tests guarded by build tags or env vars for live-network/hardware requirements; skip those and note them. Use a reasonable timeout; if something hangs, kill it and note it.
5. Optional extras, only if already installed (check with 'which' first): staticcheck ./... ; golangci-lint run ; gosec ./... . For vulnerability scanning you may try 'go run golang.org/x/vuln/cmd/govulncheck@latest ./...' — if the network or sandbox blocks it, just note that it could not run.

Convert each real problem revealed by the tools into a finding (category 'bug' for vet/test failures, 'security' for vuln/gosec hits, 'quality' for fmt/lint). Deduplicate. Ignore noise. In the summary field state exactly which tools ran, which were unavailable, and overall results (build status, test pass/fail counts).

${FINDER_RULES}`,
  },
  {
    key: 'deps',
    prompt: `You are auditing third-party dependencies of the Go module at ${ROOT}.

${CONTEXT}

Read ${ROOT}/go.mod, go.sum and go.work. Direct deps include: github.com/ethereum/go-ethereum v1.14.12, github.com/herumi/bls-eth-go-binary v1.37.0, github.com/urfave/cli/v2 v2.27.7, github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4 v1.4.1, golang.org/x/crypto v0.22.0, golang.org/x/term v0.43.0.

Use WebSearch (load it via ToolSearch with query "select:WebSearch" if needed) to check each DIRECT dependency for known CVEs / security advisories affecting the pinned version, and whether the pin is dangerously outdated for security-critical software.

CRITICAL RULE: an advisory only counts if this codebase actually imports the vulnerable package path. Grep the imports under ${ROOT} to confirm applicability before reporting (e.g. an x/crypto CVE in the ssh package is irrelevant if only scrypt/pbkdf2 are imported). For each reported finding, the evidence must show BOTH the advisory and the import that makes it applicable. Genuinely outdated security-relevant pins with relevant fixes upstream may be reported as medium/low even without a direct CVE — say why.

${FINDER_RULES}`,
  },
  {
    key: 'crosscut',
    prompt: `You are performing a cross-cutting adversarial review across the WHOLE Go module at ${ROOT} — issues that live between packages rather than inside one.

${CONTEXT}

Themes to investigate (read whatever files needed, across cmd/ and internal/):
1. End-to-end mainnet safety: trace the complete flow from CLI invocation to transaction broadcast. Could a user accidentally broadcast to mainnet, or generate deposit data with a mismatched network (fork version vs chain id vs deposit contract address)? Are network parameters in internal/network consistent between eth-deposit-gen and eth-deposit-tx? Is there any path that skips confirmation prompts?
2. Key-material lifecycle: where do BLS/secp256k1 private keys, seeds, mnemonics and passphrases live in memory across package boundaries; are they zeroized after use; can they leak via error wrapping, logging, JSON marshaling, output files, or panics?
3. Concurrency & lifecycle: goroutines, signal handling, context propagation/cancellation, cleanup ordering on early exit.
4. Build-tag parity: ledger_cgo.go vs ledger_nocgo.go — do both build, and does the nocgo path fail safely and loudly?
5. Output/file hygiene: permissions and locations of every file the tools write, especially anything containing secrets; testdata fixtures containing real-looking key material.

${FINDER_RULES}`,
  },
]

const LENSES = [
  { key: 'fact', instr: 'LENS — FACTUAL CORRECTNESS: verify the claim against the code. Does the code at the cited location actually behave as the finding states? Check the exact lines, surrounding guard clauses, and type definitions.' },
  { key: 'reach', instr: 'LENS — REACHABILITY: even if the code matches the description, can the problematic state actually be reached through real entry points (CLI flags, config files, keystore files, RPC responses, Ledger responses)? Trace the call path from an entry point to the cited code and check for earlier validation that prevents it.' },
  { key: 'impact', instr: 'LENS — IMPACT: if the issue is real and reachable, does it actually have the claimed consequence at the claimed severity? Consider what an operator would actually experience. isReal=false if the practical impact is negligible or the severity is wildly inflated beyond repair.' },
]

function refutePrompt(f, lens) {
  return `You are an adversarial verifier in a code-review pipeline. Your job is to REFUTE the following finding if at all possible. Findings that survive you will be reported to the maintainer, so a false positive you let through wastes their time, and a true positive you wrongly kill hides a real risk — judge on evidence only.

${CONTEXT}

FINDING UNDER TEST:
${JSON.stringify(f, null, 2)}

${lens.instr}

Method: read the actual code at the cited location and every piece of code needed to confirm or refute (callers, callees, type defs, tests). Be skeptical — reviewers routinely misread guard clauses, miss validation done earlier in the call chain, confuse test code with production code, or claim impossible impact. If you cannot confirm the issue with concrete evidence from the code, set isReal=false. Set isReal=true ONLY if the finding is factually accurate AND the problem can occur as described under your lens. Set adjustedSeverity to your best judgment of the true severity ('unchanged' if the stated severity is right).`
}

async function verifyFinding(f) {
  const sev = String(f.severity || 'medium').toLowerCase()
  if (sev === 'critical' || sev === 'high') {
    const votes = (await parallel(LENSES.map(lens => () =>
      agent(refutePrompt(f, lens), { label: `verify:${lens.key}:${f.id}`, phase: 'Verify', schema: VERDICT_SCHEMA })
    ))).filter(Boolean)
    const real = votes.filter(v => v.isReal).length
    const need = votes.length <= 1 ? 1 : 2
    return { ...f, verdict: { confirmed: votes.length > 0 && real >= need, votes } }
  }
  const v = await agent(refutePrompt(f, LENSES[0]), { label: `verify:fact:${f.id}`, phase: 'Verify', schema: VERDICT_SCHEMA })
  return { ...f, verdict: { confirmed: !!(v && v.isReal), votes: v ? [v] : [] } }
}

async function verifyBatch(res, sourceKey) {
  if (!res || !Array.isArray(res.findings) || res.findings.length === 0) {
    return { source: sourceKey, summary: res ? res.summary : null, confirmed: [], rejected: [] }
  }
  const fs = res.findings.slice(0, 12).map((f, i) => ({ ...f, id: `${sourceKey}-${i}`, source: sourceKey }))
  const verified = (await parallel(fs.map(f => () => verifyFinding(f)))).filter(Boolean)
  return {
    source: sourceKey,
    summary: res.summary || null,
    confirmed: verified.filter(f => f.verdict.confirmed),
    rejected: verified.filter(f => !f.verdict.confirmed),
  }
}

// ---- Phase 1+2: find, verifying each scope's findings as soon as that finder returns ----
phase('Find')
const TASKS = []
for (const u of UNITS) for (const d of DIMENSIONS) TASKS.push({ key: `${u.key}:${d.key}`, prompt: unitPrompt(u, d) })
for (const s of SPECIALS) TASKS.push({ key: s.key, prompt: s.prompt })
log(`Fanning out ${TASKS.length} finders (${UNITS.length} scopes x ${DIMENSIONS.length} dimensions + ${SPECIALS.length} sweeps)`)

const results = (await pipeline(
  TASKS,
  t => agent(t.prompt, { label: `find:${t.key}`, phase: 'Find', schema: FINDINGS_SCHEMA }),
  (res, t) => verifyBatch(res, t.key),
)).filter(Boolean)

let confirmed = results.flatMap(r => r.confirmed)
let rejected = results.flatMap(r => r.rejected)
const scopeSummaries = results.filter(r => r.summary).map(r => ({ source: r.source, summary: r.summary }))
log(`Verification done: ${confirmed.length} confirmed, ${rejected.length} refuted`)

// ---- Phase 3: completeness critic (genuinely needs the full picture) ----
phase('Critic')
const coverage = TASKS.map(t => t.key).join(', ')
const critic = await agent(`You are a completeness critic for an adversarial review of the Go module at ${ROOT}.

${CONTEXT}

Review coverage so far — scopes/dimensions run: ${coverage}.
Confirmed findings (title — severity — file):
${confirmed.map(f => `- ${f.title} — ${f.severity} — ${f.file}`).join('\n') || '(none)'}

Refuted findings (title only): ${rejected.map(f => f.title).join('; ') || '(none)'}

Question: what is MISSING from this review? Think about: files or directories nobody covered (check ${ROOT} yourself — e.g. Makefile, scripts/, testdata/, docs/ claims vs code behavior, go.work setup); classes of defect no dimension probed; suspicious absences (e.g. zero findings in a security-critical package); claims in confirmed findings that contradict each other. List up to 3 concrete, high-value follow-up investigations as gaps, each with a self-contained instruction. If coverage is genuinely complete, return an empty gaps list.`,
  { label: 'critic', phase: 'Critic', schema: CRITIC_SCHEMA })

if (critic && Array.isArray(critic.gaps) && critic.gaps.length > 0) {
  const gaps = critic.gaps.slice(0, 3)
  log(`Critic found ${gaps.length} gap(s): ${gaps.map(g => g.title).join('; ')}`)
  const gapResults = (await pipeline(
    gaps,
    (g, _o, i) => agent(`You are a follow-up investigator in an adversarial review.

${CONTEXT}

INVESTIGATION: ${g.title}
${g.instruction}

${FINDER_RULES}`, { label: `gap:${i}`, phase: 'Critic', schema: FINDINGS_SCHEMA }),
    (res, g, i) => verifyBatch(res, `gap-${i}`),
  )).filter(Boolean)
  confirmed = confirmed.concat(gapResults.flatMap(r => r.confirmed))
  rejected = rejected.concat(gapResults.flatMap(r => r.rejected))
  log(`After follow-ups: ${confirmed.length} confirmed, ${rejected.length} refuted`)
} else {
  log('Critic: no material gaps identified')
}

// ---- Phase 4: synthesize report ----
phase('Report')
const slimRejected = rejected.map(f => ({
  title: f.title, severity: f.severity, category: f.category, file: f.file, line: f.line,
  refutation: (f.verdict.votes.find(v => !v.isReal) || {}).reasoning ? String((f.verdict.votes.find(v => !v.isReal)).reasoning).slice(0, 400) : 'no surviving votes',
}))
const slimConfirmed = confirmed.map(f => ({
  id: f.id, title: f.title, severity: f.severity, category: f.category, file: f.file, line: f.line,
  description: f.description, evidence: f.evidence, recommendation: f.recommendation, source: f.source,
  votes: f.verdict.votes.map(v => ({ isReal: v.isReal, confidence: v.confidence, adjustedSeverity: v.adjustedSeverity, reasoning: String(v.reasoning).slice(0, 500) })),
}))

const reportRes = await agent(`You are the synthesis writer for an adversarial multi-agent review. Write the final report to ${ROOT}/plan/REVIEW.md using the Write tool (create the file; the plan/ directory may not exist yet — Write handles that).

${CONTEXT}

Review date: 2026-06-06.
Methodology to describe accurately: ${TASKS.length} finder agents (${UNITS.length} package scopes x 3 dimensions [bugs, security, quality] + tooling sweep + dependency audit + cross-cutting sweep), every finding adversarially verified by independent refuter agents (3-lens panel [factual/reachability/impact] with majority vote for critical/high findings; single factual-lens verifier otherwise), plus a completeness-critic round with follow-up investigations.

CONFIRMED FINDINGS (verified, with verifier votes):
${JSON.stringify(slimConfirmed, null, 1)}

REFUTED FINDINGS (killed by adversarial verification — for the appendix):
${JSON.stringify(slimRejected, null, 1)}

SCOPE SUMMARIES from finders:
${JSON.stringify(scopeSummaries, null, 1)}

Report requirements:
1. # Adversarial Code Review — go/ ... with date and a short methodology section (agent counts, verification protocol).
2. Executive summary: overall code-health verdict, the headline risks, counts by severity and category.
3. Findings table: ID, severity, category, location, title — sorted critical→info.
4. MERGE DUPLICATES first: multiple finders often report the same root cause (same file/lines, same defect) — merge into one finding, keep the best evidence, note all sources. Renumber merged findings as GO-001, GO-002, ... in severity order.
5. Detailed findings: one subsection per finding — severity (apply verifier adjustedSeverity consensus where verifiers agreed it should change; note the adjustment), location (file:line), description, evidence (code snippet), recommendation, and a one-line verification note (e.g. 'confirmed 3/3 by adversarial panel').
6. Code-quality observations section for the quality-category material plus the scope summaries' overall assessment — strengths as well as weaknesses; mention what the tooling sweep ran and its results.
7. Dependency audit section summarizing the deps findings (or stating the pins were checked and what was/wasn't applicable).
8. Recommendations: a prioritized action list (fix-now / fix-soon / consider).
9. Appendix: refuted findings — one line each (title, location, why refuted) so the maintainer sees what was adversarially killed.
Keep the tone factual, no filler. Use file:line references throughout.

After writing the file, your final message must be exactly a JSON object: {"path": "...", "merged": <number of findings after merging>, "bySeverity": {"critical": n, "high": n, "medium": n, "low": n, "info": n}, "headline": "<one-sentence top takeaway>"}`,
  { label: 'write-report', phase: 'Report' })

let reportMeta = null
try { reportMeta = JSON.parse(String(reportRes).replace(/^[^{]*/, '').replace(/[^}]*$/, '')) } catch (e) { reportMeta = { raw: String(reportRes).slice(0, 500) } }

return {
  reportPath: `${ROOT}/plan/REVIEW.md`,
  finders: TASKS.length,
  confirmedCount: confirmed.length,
  rejectedCount: rejected.length,
  bySeverity: confirmed.reduce((acc, f) => { const s = String(f.severity).toLowerCase(); acc[s] = (acc[s] || 0) + 1; return acc }, {}),
  byCategory: confirmed.reduce((acc, f) => { const c = String(f.category).toLowerCase(); acc[c] = (acc[c] || 0) + 1; return acc }, {}),
  criticAssessment: critic ? critic.assessment : null,
  reportMeta,
  confirmedTitles: confirmed.map(f => `[${f.severity}] ${f.title} (${f.file})`),
}