//! A hand-rolled JSON-RPC 2.0 client over `ureq`, implementing the builder's
//! [`EthRpc`] surface and an [`EthBroadcaster`] surface for the send/receipt
//! path.
//!
//! Ported from `go/internal/tx/rpc_client.go` and the interface half of
//! `go/internal/tx/interface.go`, with the go-ethereum `ethclient` backend
//! replaced by direct JSON-RPC calls.
//!
//! Security invariant (stronger than Go's): no [`TxError`] or [`RpcClientError`]
//! produced here ever renders the raw RPC URL. `ureq` embeds the full request
//! URL (path and query, where API keys live) in its error `Display`, so every
//! error built from a transport message is scrubbed with [`redact_url_in`]
//! against the client's URL *before* it is stored — by construction, not at a
//! later log boundary.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::builder::{CallMsg, EthRpc};
use crate::errors::TxError;
use crate::redact::{redact_url_in, safe_url};

/// An error from a single JSON-RPC call. Carries the JSON-RPC method name and a
/// pre-redacted detail string; it is used as the `source` of the builder's
/// `TxError::RpcEstimation` and broadcast errors.
#[derive(Debug, thiserror::Error)]
#[error("{method}: {detail}")]
pub struct RpcClientError {
    method: &'static str,
    /// Always already passed through [`redact_url_in`] at construction time when
    /// derived from a transport message.
    detail: String,
}

impl RpcClientError {
    /// Constructs an `RpcClientError`. Callers that build `detail` from a
    /// transport-layer message MUST redact the URL first (see
    /// [`EthClient::rpc_err`]).
    pub fn new(method: &'static str, detail: impl Into<String>) -> Self {
        RpcClientError {
            method,
            detail: detail.into(),
        }
    }

    /// The JSON-RPC method this error came from.
    pub fn method(&self) -> &str {
        self.method
    }
}

/// A JSON-friendly summary of an Ethereum transaction receipt. Field order and
/// names match Go's `tx.Receipt` for byte-identical JSON output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    pub status: u64,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "gasUsed")]
    pub gas_used: u64,
    #[serde(rename = "effectiveGasPrice", skip_serializing_if = "Option::is_none")]
    pub effective_gas_price: Option<String>,
}

/// The wire form of an `eth_getTransactionReceipt` result, where numeric fields
/// are hex-quantity strings that we decode into [`Receipt`].
#[derive(Debug, Default, Deserialize)]
struct RawReceipt {
    #[serde(rename = "transactionHash", default)]
    transaction_hash: String,
    #[serde(default)]
    status: String,
    #[serde(rename = "blockNumber", default)]
    block_number: String,
    #[serde(rename = "blockHash", default)]
    block_hash: String,
    #[serde(rename = "gasUsed", default)]
    gas_used: String,
    #[serde(rename = "effectiveGasPrice", default)]
    effective_gas_price: String,
}

/// Broadcasts a signed transaction and reads receipts via JSON-RPC.
pub trait EthBroadcaster {
    /// Decodes the 0x-prefixed RLP hex and submits it via
    /// `eth_sendRawTransaction`. Returns the tx hash as a 0x-prefixed hex
    /// string.
    fn send_raw_transaction(&self, raw_rlp: &str) -> Result<String, TxError>;
    /// Polls once for the receipt of the given tx hash. Returns `Ok(None)` if
    /// the tx is not yet mined (JSON-RPC null result).
    fn transaction_receipt(&self, tx_hash: &str) -> Result<Option<Receipt>, RpcClientError>;
    /// Returns the chain ID of the connected node.
    fn broadcaster_chain_id(&self) -> Result<u64, RpcClientError>;
    /// Closes the underlying connection. Default no-op — the transport is
    /// dropped normally.
    fn close(&self) {}
}

/// A minimal Ethereum JSON-RPC client. Satisfies both [`EthRpc`] and
/// [`EthBroadcaster`].
pub struct EthClient {
    agent: ureq::Agent,
    /// The url-normalized endpoint. Used both as the request target and as the
    /// exact redaction target, so `ureq`'s error URL always matches it and the
    /// raw form is guaranteed to be scrubbed.
    url: String,
}

impl EthClient {
    /// Dials the given RPC URL. Accepts `http`/`https` only.
    ///
    /// Divergence from Go: go-ethereum's `ethclient.Dial` also supported
    /// `ws://`/`wss://`. This client rejects any non-HTTP scheme (and any
    /// unparseable URL) with a clear `RpcDial` error whose `url` field is
    /// already reduced by [`safe_url`].
    pub fn new(rpc_url: &str) -> Result<EthClient, TxError> {
        let parsed = url::Url::parse(rpc_url)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https"));
        let parsed = match parsed {
            Some(u) => u,
            None => {
                return Err(TxError::RpcDial {
                    url: safe_url(rpc_url),
                    source: "unsupported RPC URL scheme: only http and https are supported".into(),
                });
            }
        };

        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build();

        Ok(EthClient {
            agent,
            url: parsed.to_string(),
        })
    }

    /// Builds a redacted `RpcClientError` from a transport-layer detail.
    fn rpc_err(&self, method: &'static str, detail: &str) -> RpcClientError {
        RpcClientError::new(method, redact_url_in(detail, &self.url))
    }

    /// Performs one JSON-RPC 2.0 POST and returns the `result` value (or
    /// `Value::Null` when the response has no result). A JSON-RPC `error` object
    /// is turned into a redacted `RpcClientError`.
    fn call(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcClientError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| self.rpc_err(method, &e.to_string()))?;

        let value: serde_json::Value = resp
            .into_json()
            .map_err(|e| self.rpc_err(method, &e.to_string()))?;

        if let Some(err_obj) = value.get("error") {
            if !err_obj.is_null() {
                let msg = err_obj
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown JSON-RPC error");
                return Err(self.rpc_err(method, msg));
            }
        }

        Ok(value
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    fn result_str<'a>(
        &self,
        method: &'static str,
        v: &'a serde_json::Value,
    ) -> Result<&'a str, RpcClientError> {
        v.as_str()
            .ok_or_else(|| self.rpc_err(method, "expected a hex-quantity string result"))
    }
}

// --- EthRpc ---

impl EthRpc for EthClient {
    fn suggest_gas_tip_cap(&self) -> Result<u128, RpcClientError> {
        let m = "eth_maxPriorityFeePerGas";
        let result = self.call(m, serde_json::json!([]))?;
        parse_hex_u128(m, self.result_str(m, &result)?)
    }

    fn block_base_fee(&self) -> Result<u128, RpcClientError> {
        let m = "eth_getBlockByNumber";
        let result = self.call(m, serde_json::json!(["latest", false]))?;
        let s = result
            .get("baseFeePerGas")
            .and_then(|v| v.as_str())
            .ok_or_else(|| self.rpc_err(m, "missing baseFeePerGas in block result"))?;
        parse_hex_u128(m, s)
    }

    fn pending_nonce_at(&self, account: [u8; 20]) -> Result<u64, RpcClientError> {
        let m = "eth_getTransactionCount";
        let addr = format!("0x{}", hex::encode(account));
        let result = self.call(m, serde_json::json!([addr, "pending"]))?;
        parse_hex_u64(m, self.result_str(m, &result)?)
    }

    fn estimate_gas(&self, msg: &CallMsg) -> Result<u64, RpcClientError> {
        let m = "eth_estimateGas";
        let call_obj = serde_json::json!({
            "from": format!("0x{}", hex::encode(msg.from)),
            "to": format!("0x{}", hex::encode(msg.to)),
            "value": format_hex_u128(msg.value),
            "data": format!("0x{}", hex::encode(&msg.data)),
        });
        let result = self.call(m, serde_json::json!([call_obj]))?;
        parse_hex_u64(m, self.result_str(m, &result)?)
    }

    fn chain_id(&self) -> Result<u64, RpcClientError> {
        let m = "eth_chainId";
        let result = self.call(m, serde_json::json!([]))?;
        parse_hex_u64(m, self.result_str(m, &result)?)
    }
}

// --- EthBroadcaster ---

impl EthBroadcaster for EthClient {
    fn send_raw_transaction(&self, raw_rlp: &str) -> Result<String, TxError> {
        let bytes = decode_hex(raw_rlp)
            .map_err(|e| TxError::BroadcastFailed(format!("decode rawRLP: {e}").into()))?;

        // EIP-2718 typed envelope: first byte must be the type-2 (0x02) tag.
        // Divergence from Go: go-ethereum fully re-decodes the envelope via
        // types.Transaction.UnmarshalBinary; here we validate the type tag and
        // let the node reject a malformed body.
        if bytes.first() != Some(&0x02) {
            return Err(TxError::BroadcastFailed(
                "decode EIP-2718: expected a type-2 (0x02) typed-envelope transaction".into(),
            ));
        }

        let raw_param = format!("0x{}", hex::encode(&bytes));
        let result = self
            .call("eth_sendRawTransaction", serde_json::json!([raw_param]))
            .map_err(|e| TxError::BroadcastFailed(Box::new(e)))?;

        // Divergence from Go: use the node-returned hash rather than recomputing
        // it locally. For a well-formed tx the two values are identical.
        let hash = result.as_str().ok_or_else(|| {
            TxError::BroadcastFailed(
                "eth_sendRawTransaction: node returned no transaction hash".into(),
            )
        })?;
        Ok(hash.to_string())
    }

    fn transaction_receipt(&self, tx_hash: &str) -> Result<Option<Receipt>, RpcClientError> {
        let m = "eth_getTransactionReceipt";
        let result = self.call(m, serde_json::json!([tx_hash]))?;
        if result.is_null() {
            return Ok(None);
        }
        let raw: RawReceipt =
            serde_json::from_value(result).map_err(|e| self.rpc_err(m, &e.to_string()))?;
        Ok(Some(Receipt {
            transaction_hash: raw.transaction_hash,
            status: hex_u64_or_zero(m, &raw.status)?,
            block_number: hex_u64_or_zero(m, &raw.block_number)?,
            block_hash: raw.block_hash,
            gas_used: hex_u64_or_zero(m, &raw.gas_used)?,
            effective_gas_price: if raw.effective_gas_price.is_empty() {
                None
            } else {
                Some(format_hex_u128(parse_hex_u128(
                    m,
                    &raw.effective_gas_price,
                )?))
            },
        }))
    }

    fn broadcaster_chain_id(&self) -> Result<u64, RpcClientError> {
        self.chain_id()
    }
}

// compile-time assertions mirroring Go's `var _ EthRPC/EthBroadcaster`.
const _: fn() = || {
    fn assert_impls<T: EthRpc + EthBroadcaster>() {}
    let _ = assert_impls::<EthClient>;
};

// --- hex-quantity helpers ---

/// Decodes a 0x-prefixed hex string to bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let t = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(t)
}

fn parse_hex_u64(method: &'static str, s: &str) -> Result<u64, RpcClientError> {
    let t = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(t, 16)
        .map_err(|e| RpcClientError::new(method, format!("invalid hex quantity {s:?}: {e}")))
}

fn parse_hex_u128(method: &'static str, s: &str) -> Result<u128, RpcClientError> {
    let t = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u128::from_str_radix(t, 16)
        .map_err(|e| RpcClientError::new(method, format!("invalid hex quantity {s:?}: {e}")))
}

fn hex_u64_or_zero(method: &'static str, s: &str) -> Result<u64, RpcClientError> {
    if s.is_empty() {
        return Ok(0);
    }
    parse_hex_u64(method, s)
}

fn format_hex_u128(v: u128) -> String {
    format!("0x{v:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    // A dependency-free HTTP stub that answers exactly one JSON-RPC POST with the
    // given raw JSON body, then closes. Returns the bound URL.
    fn spawn_stub(response_body: &'static str) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Drain what the client sent (small localhost request fits one read).
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), handle)
    }

    // Adapted from rpc_client_test.go: one happy-path JSON-RPC round trip.
    #[test]
    fn chain_id_round_trip() {
        // 0x4268 == 17000 (Holesky).
        let (url, handle) = spawn_stub(r#"{"jsonrpc":"2.0","id":1,"result":"0x4268"}"#);
        let client = EthClient::new(&url).expect("new");
        let id = client.chain_id().expect("chain_id");
        assert_eq!(id, 17000);
        handle.join().unwrap();
    }

    // Divergence guard: ws:// is rejected at construction (Go accepted it). The
    // reported url is reduced to scheme://host and never carries the path key.
    #[test]
    fn new_rejects_ws_scheme() {
        let err = match EthClient::new("ws://node.example/ws/SECRETKEY") {
            Ok(_) => panic!("expected ws:// to be rejected"),
            Err(e) => e,
        };
        assert!(
            !err.to_string().contains("SECRETKEY"),
            "RpcDial leaked the key: {err}"
        );
        match err {
            TxError::RpcDial { url, .. } => assert_eq!(url, "ws://node.example"),
            other => panic!("expected RpcDial, got {other}"),
        }
    }

    // The by-construction invariant: an EthClient built against a URL with an
    // embedded key must never surface that key in any error Display, even for the
    // real transport-failure channel (connection refused on a closed port).
    //
    // Go: TestRedactURLString_RealDialError — including its "probe assumption
    // broken" precondition so the redaction assertion can never pass vacuously.
    #[test]
    fn error_never_contains_raw_url_key() {
        const SECRET: &str = "SECRETKEY123";
        // Port 1 is reserved/closed; the connect fails fast.
        let raw = format!("http://127.0.0.1:1/v3/{SECRET}");
        let client = EthClient::new(&raw).expect("new");

        // Precondition (white-box): the un-redacted transport error DOES carry
        // the URL — and hence the key. If ureq ever stops attaching the URL, this
        // fires instead of the redaction assertion below silently passing while
        // doing nothing.
        let unredacted = match client
            .agent
            .post(&client.url)
            .send_json(serde_json::json!({}))
        {
            Ok(_) => panic!("expected the closed port to fail"),
            Err(e) => e.to_string(),
        };
        assert!(
            unredacted.contains(SECRET),
            "probe assumption broken: transport error no longer carries the URL: {unredacted:?}"
        );

        let err = client.chain_id().expect_err("closed port must fail");
        let rendered = err.to_string();
        assert!(
            !rendered.contains(SECRET),
            "RpcClientError leaked the secret: {rendered:?}"
        );

        // And through the TxError wrap the builder would apply.
        let wrapped = TxError::RpcEstimation {
            call: "ChainID",
            source: Box::new(err),
        };
        assert!(
            !wrapped.to_string().contains(SECRET),
            "wrapped TxError leaked the secret: {}",
            wrapped
        );
    }

    // send_raw_transaction rejects a non-type-2 envelope before any network call.
    #[test]
    fn send_raw_transaction_rejects_non_type2() {
        let client = EthClient::new("http://127.0.0.1:1").expect("new");
        let err = client.send_raw_transaction("0x01aabbcc").unwrap_err();
        assert!(matches!(err, TxError::BroadcastFailed(_)));
        assert!(err.to_string().contains("EIP-2718"), "got: {err}");
    }

    // send_raw_transaction rejects non-hex input before any network call.
    #[test]
    fn send_raw_transaction_rejects_bad_hex() {
        let client = EthClient::new("http://127.0.0.1:1").expect("new");
        let err = client.send_raw_transaction("0xzz").unwrap_err();
        assert!(matches!(err, TxError::BroadcastFailed(_)));
        assert!(err.to_string().contains("decode rawRLP"), "got: {err}");
    }

    // Adapted from TestDecodeRawRLP_EIP2718: the phase-3 signed golden's rawRLP is
    // a valid EIP-2718 type-2 envelope (first byte 0x02). Full RLP decoding is
    // NOT PORTED (no go-ethereum types.Transaction in Rust).
    //
    // NOT PORTED: TestDecodeRawRLP_RLPDecodeBytes_Breaks — it asserts go-ethereum's
    // rlp.DecodeBytes rejects the type-2 envelope; there is no equivalent bare-RLP
    // decoder in this crate to demonstrate that failure against.
    #[test]
    fn golden_raw_rlp_is_eip2718() {
        const GOLDEN: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/phase3/holesky/signed_tx_golden.json"
        );
        let raw = std::fs::read(GOLDEN).expect("read signed golden");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("parse golden");
        let raw_rlp = v
            .get("rawRLP")
            .and_then(|x| x.as_str())
            .expect("golden has rawRLP");
        let bytes = decode_hex(raw_rlp).expect("decode rawRLP");
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x02, "expected EIP-2718 type byte 0x02");
    }
}
