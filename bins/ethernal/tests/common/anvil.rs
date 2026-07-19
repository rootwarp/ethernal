//! Anvil subprocess harness for the live e2e tier.
//!
//! Mirrors [`super::Stub`]'s lifecycle discipline (spawn / kill+reap on `Drop`)
//! over the Foundry `anvil` binary. Modeled on alloy `node-bindings`: `--port 0`,
//! scrape `Listening on 127.0.0.1:<port>` from stdout, drain stdout on a background
//! thread (foundry #3414), and RPC-poll `eth_chainId` as the readiness backstop.
//!
//! Skip-with-notice when `anvil` is absent (D-3/A-6) so a contributor without
//! Foundry still gets a green `--ignored` run. Panics only on a genuine
//! spawn/readiness failure when the binary *is* present.
//!
//! Hand-rolled dependency-free JSON-RPC POST (D-7) — requires only `anvil`, not
//! `cast`. Reuses the same raw-HTTP style the `Stub` proves works.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Default chain id for the live tier: hoodi (A-3).
pub const DEFAULT_CHAIN_ID: u64 = 560048;

/// How long to wait for the `Listening on` line and subsequent RPC readiness.
const SPAWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Guard over a live `anvil` child process.
pub struct Anvil {
    url: String,
    child: Child,
    /// Background thread that drains anvil stdout to EOF so the pipe never fills.
    drain: Option<JoinHandle<()>>,
}

impl Anvil {
    /// Skip-aware spawn: returns `None` (after an `eprintln!` notice) when the
    /// `anvil` binary is absent; panics only on a genuine spawn/readiness failure
    /// when anvil *is* present. `chain_id` is typically [`DEFAULT_CHAIN_ID`].
    pub fn try_spawn(chain_id: u64) -> Option<Anvil> {
        if !anvil_on_path() {
            eprintln!(
                "anvil: binary not found on PATH — skipping live anvil test \
                 (install Foundry or run without --ignored)"
            );
            return None;
        }

        let mut child = Command::new("anvil")
            .args(["--chain-id", &chain_id.to_string(), "--port", "0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("anvil: spawn failed: {e}"));

        let stdout = child.stdout.take().expect("anvil: stdout piped");

        // Drain thread: scrape the first "Listening on …" line for the bound
        // port, then keep reading to EOF so the pipe buffer never fills.
        let (tx, rx) = mpsc::channel::<u16>();
        let drain = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let mut sent = false;
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if !sent {
                    if let Some(port) = parse_listening_port(&line) {
                        let _ = tx.send(port);
                        sent = true;
                    }
                }
            }
        });

        let port = match rx.recv_timeout(SPAWN_TIMEOUT) {
            Ok(p) => p,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = drain.join();
                panic!(
                    "anvil: timed out waiting for 'Listening on 127.0.0.1:<port>' \
                     within {SPAWN_TIMEOUT:?}"
                );
            }
        };

        let url = format!("http://127.0.0.1:{port}");
        let anvil = Anvil {
            url,
            child,
            drain: Some(drain),
        };

        // RPC-poll eth_chainId as the readiness backstop.
        let deadline = Instant::now() + SPAWN_TIMEOUT;
        loop {
            match try_rpc(&anvil.url, "eth_chainId", Value::Array(vec![])) {
                Ok(result) => {
                    let got = parse_hex_u64(&result).unwrap_or_else(|| {
                        panic!("anvil: eth_chainId returned non-hex: {result:?}")
                    });
                    assert_eq!(
                        got, chain_id,
                        "anvil: eth_chainId mismatch (got {got}, want {chain_id})"
                    );
                    break;
                }
                Err(_) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    // Drop kills the child.
                    drop(anvil);
                    panic!("anvil: eth_chainId readiness poll failed: {e}");
                }
            }
        }

        Some(anvil)
    }

    /// The `http://127.0.0.1:PORT` URL to pass as `--rpc-url`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Hand-rolled dependency-free JSON-RPC POST. Returns the `result` field.
    /// Panics on transport or JSON-RPC errors.
    pub fn rpc(&self, method: &str, params: Value) -> Value {
        try_rpc(&self.url, method, params).unwrap_or_else(|e| {
            panic!("anvil rpc {method}: {e}");
        })
    }

    /// Funds `addr` with `wei` (hex quantity or decimal string) via `anvil_setBalance`.
    pub fn set_balance(&self, addr: &str, wei: &str) {
        let _ = self.rpc("anvil_setBalance", serde_json::json!([addr, wei]));
    }

    /// Sets the account nonce of `addr` via `anvil_setNonce`.
    pub fn set_nonce(&self, addr: &str, n: u64) {
        let _ = self.rpc(
            "anvil_setNonce",
            serde_json::json!([addr, format!("0x{n:x}")]),
        );
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(h) = self.drain.take() {
            let _ = h.join();
        }
    }
}

/// True when an `anvil` binary resolves and reports a version.
fn anvil_on_path() -> bool {
    Command::new("anvil")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Parse `Listening on 127.0.0.1:<port>` (or any `host:port` after the prefix).
fn parse_listening_port(line: &str) -> Option<u16> {
    let rest = line.trim().strip_prefix("Listening on ")?;
    let port_str = rest.rsplit_once(':')?.1;
    port_str.parse().ok()
}

/// Parse a 0x-prefixed hex quantity into u64.
fn parse_hex_u64(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

/// One JSON-RPC 2.0 POST against `url`. Returns the `result` value.
fn try_rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
    let host_port = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let payload = body.to_string();

    let mut stream = TcpStream::connect(host_port).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

    let req = format!(
        "POST / HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len(),
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;

    let resp_body = read_http_body(&mut stream).ok_or_else(|| "empty response".to_string())?;
    let resp: Value = serde_json::from_slice(&resp_body).map_err(|e| format!("json: {e}"))?;

    if let Some(err) = resp.get("error") {
        return Err(format!("json-rpc error: {err}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| format!("missing result: {resp}"))
}

/// Reads an HTTP/1.1 response and returns its body bytes (mirrors Stub's reader).
fn read_http_body(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];

    let header_end = loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let content_length = header_str
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if content_length > 0 {
        body.truncate(content_length);
    }
    Some(body)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
