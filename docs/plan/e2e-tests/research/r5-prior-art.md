# R5 — Prior art

## Verdict (up front)

Three actionable takeaways: (1) **ethstaker's deposit CLI does NOT use `pexpect`** — it scrapes the mnemonic from stdout and echoes it back at the re-entry prompt over plain pipes, because that CLI reads a pipe, not `/dev/tty`; ethernal opens `/dev/tty`, so it needs the PTY that ethstaker avoids. (2) **The alloy `node-bindings` anvil pattern** (spawn the binary, read `Listening on <addr>` from stdout, use `--port 0`) is the model for ethernal's live anvil harness. (3) **reth gates node/network tests with `#[ignore]`**, run out-of-band — confirming R3's choice.

---

## ethstaker / eth-staking-deposit-cli (interactive-ceremony testing)

`ethstaker/ethstaker-deposit-cli`, `tests/test_cli/test_new_mnemonic.py`. Two tiers, **no `pexpect`** (repo-wide search: 0 hits):

1. **Fast unit tier — Click `CliRunner` with scripted stdin.** Newline-joined inputs (`language, count, network, password, password, mnemonic, ''`) fed as `runner.invoke(cli, args, input=data)`; the generate-then-re-enter flow is handled by **monkeypatching `get_mnemonic`** to a fixed phrase and feeding that same phrase back. Pure captured stdin/stdout — no terminal.
2. **Real-binary e2e tier — subprocess with piped stdin/stdout, hand-rolled expect.** `asyncio.create_subprocess_shell("./deposit.sh … new-mnemonic …")`, reads stdout line by line, matches on the CLI's own **localized prompt strings** (`msg_mnemonic_presentation` flips a capture flag to grab the generated mnemonic; `msg_mnemonic_retype_prompt` triggers writing it back to `proc.stdin`). This is a wait-for-prompt loop keyed on prompt text, not fixed sleeps.

**Takeaway for ethernal:** the *shape* is the same one R1 prescribes (capture the displayed mnemonic, replay it at the re-entry prompt, key on prompt strings). The **difference that forces a PTY**: ethstaker's CLI reads a plain pipe and never opens `/dev/tty`, so pipes suffice for it. ethernal reads echo-off secrets from `/dev/tty` and gates on `isatty` — so ethernal cannot use ethstaker's pipe trick and must supply a controlling terminal (R1). Their monkeypatch-the-mnemonic tier has no ethernal analog: ethernal ships **no** entropy-injection hook (C-2/A-5), which is exactly why ethernal must capture the live mnemonic instead of fixing it.

---

## foundry / reth (node-backed integration testing)

- **foundry — anvil in-process (library).** Anvil's tests (`crates/anvil/tests/it/`) start the node with `spawn(NodeConfig::test())`, which binds an **ephemeral port** for parallelism, and connect via `handle.http_endpoint()`. Not applicable directly (ethernal shells out to the `anvil` *binary*, has no Rust EVM dep — C-1), but confirms ephemeral-port-per-test is the norm.
- **alloy `node-bindings` — anvil binary as a subprocess (the model for ethernal).** `crates/node-bindings/src/nodes/anvil.rs`: `Command::new("anvil").stdout(Stdio::piped()).spawn()`, then read stdout for `Listening on <SocketAddr>` to learn the **actual bound port** (supports `--port 0` for a race-free ephemeral port) and use that line as the readiness signal; a startup timeout kills the child on overrun. **Gotcha:** keep draining anvil's stdout or its pipe buffer fills and anvil blocks (foundry #3414). This is the recommended pattern for `tests/common/anvil.rs` (see [r2-anvil-ci.md](r2-anvil-ci.md)).
- **reth — `#[ignore]` for network/online tests.** Confirmed across `crates/net/**/tests/it/` and examples (`test_mainnet_lookup`, `get_external_ip`, p2p connect). Default `cargo test` skips them; a separate run does `--include-ignored`/`--ignored`. Directly corroborates R3's `#[ignore]` gate (over cargo features) and R2's separate-job cadence. (The `#[ignore]` mechanism is verified from source; the "nightly vs per-PR" schedule is the standard convention, not read from their CI YAML.)

---

## Rust PTY-expect crates (fallback options for R1)

- **rexpect** (v0.7.1, maintained, ~1.6M downloads) — pexpect-style expect over a real PTY; the most-used crate for exactly this job. The R1 fallback if the hand-roll ever flakes.
- **expectrl** (v0.9.0, maintained, ~487K downloads) — richer/async expect; solid, slightly less adoption.
- **portable-pty** (v0.9.0, wezterm, maintained) — low-level cross-platform PTY primitive only, **not** an expect library; you still write the match loop. No advantage over the hand-roll.

---

## Verdict

The prescribed approach matches proven prior art: capture-and-replay the mnemonic keyed on prompt strings (ethstaker), drive the anvil *binary* via the alloy spawn+`Listening on`+`--port 0` readiness pattern, and gate the heavy tier with `#[ignore]` run out-of-band (reth). The one place ethernal diverges from ethstaker — needing a real controlling terminal — is forced by ethernal's `/dev/tty` usage and is precisely what the R1 hand-rolled PTY supplies.

## Consequences for architecture

- Model `tests/common/anvil.rs` on alloy `node-bindings`: spawn the `anvil` binary, `--port 0`, read `Listening on` for port + readiness, drain stdout, kill+reap on drop.
- Reuse the ethstaker capture-and-replay shape in the PTY ceremony tests (key on the exact prompt strings from [r1-pty-driver.md](r1-pty-driver.md)); there is no fixed-mnemonic shortcut (no entropy injection).
- `#[ignore]` + out-of-band job for the live tier (reth-confirmed); `rexpect` is the named PTY fallback if the hand-roll flakes.
