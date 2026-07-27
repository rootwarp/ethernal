//! Shared test scaffolding for the `ethernal` integration tests.
//!
//! Because each integration test file (`tests/*.rs`) compiles `mod common;` into
//! its own test binary, a given file uses only a subset of these helpers — hence
//! the crate-wide `dead_code` allow. The main pieces are:
//!
//!   1. `ethernal()` — a `Command` for the built binary with every
//!      `ETHERNAL_TX_*` env-var scrubbed, so the flags' `.env(...)` fallbacks
//!      never leak the runner's environment into a negative test.
//!   2. `secret_file()` — write secret fixture bytes at mode 0600 (Unix) for
//!      file-flag tests; never land payload on a umask-default inode.
//!   3. Fixture-path accessors (workspace `rust/testdata/**` read-only, plus the
//!      in-crate `tests/testdata/**` pair copied from the Go tree).
//!   4. `Stub` — a dependency-free multi-request JSON-RPC 2.0 stub server the
//!      binary can be pointed at via `--rpc-url`, driving the REAL client.

#![allow(dead_code)]

// Live-tier anvil harness (unix only — shells out to the Foundry `anvil` binary).
#[cfg(unix)]
pub mod anvil;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::Value;

/// The synthetic secp256k1 key that produced the phase-3 signed golden. Any
/// valid key works for tests that only check field presence; this one also makes
/// the signed-golden byte-identity test deterministic.
pub const PHASE3_KEY: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";

/// The hash embedded in the phase-3 signed golden (Go's `fakeTxHash`).
pub const PHASE3_TX_HASH: &str =
    "0xe00d2e5332902ab8638737b7e99df242306ee82838401f15f92eda9a64f9893a";

/// Every env var that a build/send flag falls back to. Scrubbed from every test
/// Command so a set variable in the runner cannot mask a missing-flag error.
const ETHERNAL_ENV_VARS: &[&str] = &[
    "ETHERNAL_TX_INPUT_FILE",
    "ETHERNAL_TX_NETWORK",
    "ETHERNAL_TX_OUTPUT",
    "ETHERNAL_TX_INDEX",
    "ETHERNAL_TX_RPC_URL",
    "ETHERNAL_TX_GAS_LIMIT",
    "ETHERNAL_TX_MAX_FEE_PER_GAS",
    "ETHERNAL_TX_MAX_PRIORITY_FEE_PER_GAS",
    "ETHERNAL_TX_NONCE",
    "ETHERNAL_TX_FROM",
    "ETHERNAL_TX_PRIVATE_KEY",
];

/// Returns a `Command` for the built `ethernal` binary, with all
/// `ETHERNAL_TX_*` env vars removed (PATH and friends are preserved so the
/// fake-`deposit`-script test still works).
pub fn ethernal() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ethernal"));
    for v in ETHERNAL_ENV_VARS {
        c.env_remove(v);
    }
    c
}

/// Writes `bytes` to `dir/name` at mode 0600 and returns the path. Every test
/// secret file must go through this: a 0644 file emits the FR-17 WARNING and
/// breaks the caller's own WARNING count.
///
/// Writes exactly `bytes` with no trailing newline added — a test that wants a
/// trailing `\n` (to exercise FR-8) must include it in `bytes`.
///
/// On Unix the file is created with `OpenOptionsExt::mode(0o600)` and then
/// `set_permissions(0o600)` **before** any payload is written, matching
/// production secret writers (`fs_util` / `open_0600` + `write_atomic` chmod-
/// before-write). Mode enforcement is Unix-only (FR-17 scope).
pub fn secret_file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path).expect("create secret file");
    // Force 0600 before write_all so secret bytes never land at umask-default
    // mode (typically 0644). Create-time mode alone can still be umask-masked.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        f.set_permissions(perms).expect("chmod 0600 secret file");
    }
    f.write_all(bytes).expect("write secret file");
    path
}

#[test]
fn secret_file_mode_0600_no_trailing_newline_inside_tempdir() {
    let dir = TempDir::new("secret-file");
    // Deliberately no trailing `\n` — the helper must not add one.
    let bytes = b"0xdeadbeef";
    assert!(
        !bytes.ends_with(b"\n"),
        "test fixture must not already end with newline"
    );

    let path = secret_file(&dir, "key.hex", bytes);

    assert!(
        path.starts_with(dir.path()),
        "returned path {path:?} is not inside {:?}",
        dir.path()
    );

    let got = std::fs::read(&path).expect("read secret file back");
    assert_eq!(got.as_slice(), bytes, "bytes must be written verbatim");
    assert!(
        !got.ends_with(b"\n"),
        "helper must not append a trailing newline"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be mode 0600");
    }
}

/// Like [`ethernal`], but the child runs in a **new session with no controlling
/// terminal**.
///
/// Needed for tests that assert the interactive-prompt failure path
/// (`TermPromptSource` / `NewKeystorePassphrase` open `/dev/tty`). Piping
/// stdin/stdout via [`.output()`](std::process::Command::output) is **not**
/// enough: the child still inherits the test runner's controlling TTY, so under
/// an interactive `cargo test` / `make test` the prompt blocks forever waiting
/// for a passphrase on the real terminal. `setsid(2)` drops that inheritance so
/// `open("/dev/tty")` fails with ENXIO → `NoTty` → exit 2 naming
/// `--passphrase-env`.
#[cfg(unix)]
pub fn ethernal_no_tty() -> Command {
    use std::os::unix::process::CommandExt;

    let mut c = ethernal();
    // SAFETY: pre_exec runs in the forked child between fork and exec; only
    // async-signal-safe calls are allowed. setsid(2) is async-signal-safe.
    unsafe {
        c.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c
}

// --- fixture paths ---

/// The workspace `rust/testdata` directory (holds phase2/phase3/hoodi/mainnet).
pub fn workspace_testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// The in-crate `tests/testdata` directory (the Go-tree fixtures copied in).
pub fn crate_testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata")
}

/// The holesky deposit_data fixture (Go: `testdata/deposit-fixture.json`).
pub fn deposit_fixture() -> PathBuf {
    crate_testdata().join("deposit-fixture.json")
}

/// The golden unsigned tx for building `deposit_fixture` on holesky with the
/// static defaults (Go: `testdata/unsigned-tx-golden.json`).
pub fn unsigned_tx_golden() -> PathBuf {
    crate_testdata().join("unsigned-tx-golden.json")
}

/// The phase-2 holesky deposit fixture and its byte-identical unsigned golden.
pub fn phase2_fixture() -> PathBuf {
    workspace_testdata().join("phase2/holesky/deposit_data_single.json")
}
pub fn phase2_golden() -> PathBuf {
    workspace_testdata().join("phase2/holesky/unsigned_tx_golden.json")
}

/// The phase-3 holesky unsigned tx and its signed golden (signed with PHASE3_KEY).
pub fn phase3_unsigned() -> PathBuf {
    workspace_testdata().join("phase3/holesky/unsigned_tx.json")
}
pub fn phase3_signed_golden() -> PathBuf {
    workspace_testdata().join("phase3/holesky/signed_tx_golden.json")
}

/// The hoodi keystore fixtures used by the real-pipeline gen test.
pub fn hoodi_keystores() -> PathBuf {
    workspace_testdata().join("hoodi/keystores")
}
pub fn hoodi_passphrase() -> String {
    let raw = std::fs::read_to_string(workspace_testdata().join("hoodi/passphrase.txt"))
        .expect("read hoodi passphrase");
    raw.trim_end_matches(['\r', '\n']).to_string()
}
pub fn hoodi_pubkey() -> String {
    let raw = std::fs::read_to_string(workspace_testdata().join("hoodi/pubkeys.txt"))
        .expect("read hoodi pubkeys");
    raw.trim().to_string()
}

/// Golden Launchpad deposit JSON for the hoodi real-pipeline gen test (T-7).
pub fn hoodi_expected_deposit_data() -> PathBuf {
    workspace_testdata().join("hoodi/deposit_data-expected.json")
}

/// The mainnet keystore fixtures used by the mainnet gen guard/golden tests (T-8).
pub fn mainnet_keystores() -> PathBuf {
    workspace_testdata().join("mainnet/keystores")
}
pub fn mainnet_passphrase() -> String {
    let raw = std::fs::read_to_string(workspace_testdata().join("mainnet/passphrase.txt"))
        .expect("read mainnet passphrase");
    raw.trim_end_matches(['\r', '\n']).to_string()
}
pub fn mainnet_pubkey() -> String {
    let raw = std::fs::read_to_string(workspace_testdata().join("mainnet/pubkeys.txt"))
        .expect("read mainnet pubkeys");
    raw.trim().to_string()
}

/// Golden Launchpad deposit JSON for the mainnet real-pipeline gen test (T-8).
pub fn mainnet_expected_deposit_data() -> PathBuf {
    workspace_testdata().join("mainnet/deposit_data-expected.json")
}

// --- unique temp dirs (auto-cleaned) ---

/// A uniquely named temp directory that removes itself on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a fresh unique directory under the system temp dir.
    pub fn new(label: &str) -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "ethernal-test-{label}-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// A child path inside this temp dir (not created).
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Writes `bytes` to `name` inside this dir and returns the full path.
    pub fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.join(name);
        std::fs::write(&p, bytes).expect("write temp file");
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Writes the phase-3 signed golden to a temp file (Go: `writeTempSignedTx`) and
/// returns `(dir, path)`. The dir must be kept alive for the file to survive.
pub fn write_temp_signed_tx() -> (TempDir, PathBuf) {
    let dir = TempDir::new("signed");
    let bytes = std::fs::read(phase3_signed_golden()).expect("read signed golden");
    let path = dir.write("signed.json", &bytes);
    (dir, path)
}

// --- JSON-RPC stub server ---

/// A canned reply for one JSON-RPC method.
pub enum Reply {
    /// Becomes the `result` field of the JSON-RPC response.
    Ok(Value),
    /// Becomes a JSON-RPC `error` object with the given message.
    Err(String),
}

/// A dependency-free JSON-RPC 2.0 stub over a localhost `TcpListener`. It answers
/// one request per connection (the response carries `Connection: close`, matching
/// the prior-art stub in the tx crate), dispatching each `method` through the
/// supplied handler and recording every `(method, params)` pair for assertions.
pub struct Stub {
    /// The `http://127.0.0.1:PORT` URL to pass as `--rpc-url`.
    pub url: String,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Stub {
    /// Starts a stub whose handler maps `(method, params)` to a [`Reply`].
    pub fn start<F>(handler: F) -> Stub
    where
        F: Fn(&str, &Value) -> Reply + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let addr = listener.local_addr().expect("local_addr");
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking on listener");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let calls_thread = Arc::clone(&calls);
        let shutdown_thread = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            let handler = handler;
            while !shutdown_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        handle_conn(stream, &handler, &calls_thread);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Stub {
            url: format!("http://{addr}"),
            calls,
            shutdown,
            handle: Some(handle),
        }
    }

    /// A stub that serves the five build-resolution calls with fixed values plus
    /// the given chain ID; every other method returns a JSON-RPC error.
    pub fn build_ok(chain_id: u64, tip: u128, base_fee: u128, nonce: u64, gas: u64) -> Stub {
        Stub::start(move |method, _params| match method {
            "eth_chainId" => Reply::Ok(Value::String(hex_u64(chain_id))),
            "eth_maxPriorityFeePerGas" => Reply::Ok(Value::String(hex_u128(tip))),
            "eth_getBlockByNumber" => Reply::Ok(serde_json::json!({
                "baseFeePerGas": hex_u128(base_fee),
            })),
            "eth_getTransactionCount" => Reply::Ok(Value::String(hex_u64(nonce))),
            "eth_estimateGas" => Reply::Ok(Value::String(hex_u64(gas))),
            other => Reply::Err(format!("unexpected method {other}")),
        })
    }

    /// The recorded `(method, params)` list, in call order.
    pub fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().unwrap().clone()
    }

    /// Just the method names, in call order.
    pub fn methods(&self) -> Vec<String> {
        self.calls().into_iter().map(|(m, _)| m).collect()
    }

    /// The params of the first recorded call to `method`, if any.
    pub fn params_of(&self, method: &str) -> Option<Value> {
        self.calls()
            .into_iter()
            .find(|(m, _)| m == method)
            .map(|(_, p)| p)
    }

    /// True if `method` was called at least once.
    pub fn called(&self, method: &str) -> bool {
        self.methods().iter().any(|m| m == method)
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_conn<F>(
    mut stream: std::net::TcpStream,
    handler: &F,
    calls: &Arc<Mutex<Vec<(String, Value)>>>,
) where
    F: Fn(&str, &Value) -> Reply,
{
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();

    let body = match read_http_body(&mut stream) {
        Some(b) => b,
        None => return,
    };

    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let method = req
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let id = req.get("id").cloned().unwrap_or(Value::from(1));

    calls.lock().unwrap().push((method.clone(), params.clone()));

    let response_value = match handler(&method, &params) {
        Reply::Ok(result) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }),
        Reply::Err(message) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32000, "message": message },
        }),
    };
    let payload = response_value.to_string();
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

/// Reads an HTTP/1.1 request and returns its body bytes. Reads until the header
/// terminator, parses `Content-Length`, then reads exactly that many body bytes
/// (a single `read` is not guaranteed to capture the whole request).
fn read_http_body(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];

    // Read until we have the full header block.
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

/// Formats a u64 as a 0x-prefixed hex quantity.
pub fn hex_u64(v: u64) -> String {
    format!("0x{v:x}")
}

/// Formats a u128 as a 0x-prefixed hex quantity.
pub fn hex_u128(v: u128) -> String {
    format!("0x{v:x}")
}
