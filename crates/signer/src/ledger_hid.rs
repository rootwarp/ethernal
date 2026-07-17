//! Real Ledger HID transport (cargo feature `ledger`), the counterpart of
//! Go's `ledger_cgo.go` which wrapped go-ethereum's `accounts/usbwallet`.
//!
//! The USB HID framing and the Ethereum-app APDU protocol are reproduced
//! from go-ethereum v1.14.12 `accounts/usbwallet/{hub,ledger}.go`:
//!
//! - HID frames are 64 bytes: header `01 01 05 <seq_be16>` then payload
//!   (a leading `0x00` report-ID byte is prepended on write, as hidapi
//!   requires for devices without numbered reports);
//! - the APDU stream is `<len_be16> E0 <ins> <p1> <p2> <data_len> <data>`;
//! - sign-tx (INS `0x04`) payload is the BIP-32 path (count byte + 4-byte
//!   big-endian components) followed by the FULL typed signing payload —
//!   for EIP-2718 type-2 transactions this INCLUDES the leading `0x02`
//!   type byte (geth appends `tx.Type()` in front of the RLP list) — sent
//!   in 255-byte chunks (P1 `0x00` first, `0x80` continuation);
//! - the response is `v(1) || r(32) || s(32)`; for type-2 transactions `v`
//!   is the y-parity bit.
//!
//! Divergences from geth (documented deliberately):
//! - the APDU status word is checked here and rendered as
//!   `"ledger: apdu status <hex>"`, so device refusals (6985, 6a80, ...)
//!   flow into the same textual classification heuristics `ledger.rs`
//!   applies to Go's usbwallet errors;
//! - `open` only claims the HID handle; the app-presence probing that geth
//!   spreads across `Open`/`Status` happens in `status` (APDU
//!   get-configuration), which the orchestration calls right after `open`.
//!
//! This path is COMPILE-VERIFIED ONLY: hardware validation is deferred,
//! same caveat as the Go TODO(3.6).

use std::ffi::CString;
use std::sync::Arc;

use hidapi::{HidApi, HidDevice};

use crate::errors::SignerError;
use crate::ledger::{
    LedgerHub, LedgerSignature, LedgerTransportError, LedgerWallet, DEFAULT_DERIVATION_PATH,
};
use crate::parse::ParsedTx;
use crate::rlp;

/// Ledger USB vendor ID.
const LEDGER_VENDOR_ID: u16 = 0x2c97;
/// The HID usage page of the Ledger wallet interface (macOS/Windows match
/// on this; Linux exposes it as interface 0).
const LEDGER_USAGE_PAGE: u16 = 0xffa0;
const LEDGER_INTERFACE: i32 = 0;
/// Product IDs from geth `usbwallet.NewLedgerHub` (Blue, Nano S/X/S+/FTS in
/// their plain, +U2F+WebUSB and +WebUSB variants).
const LEDGER_PRODUCT_IDS: &[u16] = &[
    0x0000, 0x0001, 0x0004, 0x0005, 0x0006, // original
    0x0015, 0x1015, 0x4015, 0x5015, 0x6015, // HID + U2F + WebUSB
    0x0011, 0x1011, 0x4011, 0x5011, 0x6011, // HID + WebUSB
];

const APDU_CLA: u8 = 0xe0;
const INS_RETRIEVE_ADDRESS: u8 = 0x02;
const INS_SIGN_TRANSACTION: u8 = 0x04;
const INS_GET_CONFIGURATION: u8 = 0x06;
const P1_FIRST_CHUNK: u8 = 0x00;
const P1_CONT_CHUNK: u8 = 0x80;
const HID_FRAME_SIZE: usize = 64;
const HID_FRAME_HEADER: [u8; 3] = [0x01, 0x01, 0x05]; // channel 0x0101, tag 0x05
const APDU_CHUNK: usize = 255;
const SW_OK: u16 = 0x9000;

fn transport_err(msg: impl Into<String>) -> LedgerTransportError {
    LedgerTransportError(msg.into())
}

/// Creates the real HID hub (the default hub factory under the `ledger`
/// feature).
pub(crate) fn new_hid_hub() -> Result<Box<dyn LedgerHub>, SignerError> {
    let api = HidApi::new().map_err(|e| SignerError::Msg(format!("hidapi init: {e}")))?;
    Ok(Box::new(HidHub { api: Arc::new(api) }))
}

struct HidHub {
    api: Arc<HidApi>,
}

impl LedgerHub for HidHub {
    fn wallets(self: Box<Self>) -> Vec<Box<dyn LedgerWallet>> {
        let mut out: Vec<Box<dyn LedgerWallet>> = Vec::new();
        for info in self.api.device_list() {
            if info.vendor_id() != LEDGER_VENDOR_ID {
                continue;
            }
            if !LEDGER_PRODUCT_IDS.contains(&info.product_id()) {
                continue;
            }
            // geth: "Windows and Macos use UsageID matching, Linux uses
            // Interface matching".
            if info.usage_page() != LEDGER_USAGE_PAGE && info.interface_number() != LEDGER_INTERFACE
            {
                continue;
            }
            out.push(Box::new(HidWallet {
                api: Arc::clone(&self.api),
                path: info.path().to_owned(),
                device: None,
            }));
        }
        out
    }
}

struct HidWallet {
    api: Arc<HidApi>,
    path: CString,
    device: Option<HidDevice>,
}

impl HidWallet {
    fn device(&self) -> Result<&HidDevice, LedgerTransportError> {
        self.device
            .as_ref()
            .ok_or_else(|| transport_err("ledger: device not open"))
    }

    /// Performs one APDU exchange over the Ledger HID framing
    /// (geth `ledgerExchange`).
    fn exchange(
        &self,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, LedgerTransportError> {
        debug_assert!(data.len() <= APDU_CHUNK);
        let device = self.device()?;

        // APDU stream: length prefix + header + payload.
        let mut apdu = Vec::with_capacity(7 + data.len());
        let apdu_len = (5 + data.len()) as u16;
        apdu.extend_from_slice(&apdu_len.to_be_bytes());
        apdu.extend_from_slice(&[APDU_CLA, ins, p1, p2, data.len() as u8]);
        apdu.extend_from_slice(data);

        // Stream out in 64-byte frames, each prefixed with the 0x00
        // report-ID byte hidapi expects.
        let space = HID_FRAME_SIZE - 5;
        for (seq, chunk) in apdu.chunks(space).enumerate() {
            let mut frame = Vec::with_capacity(1 + HID_FRAME_SIZE);
            frame.push(0x00); // report ID
            frame.extend_from_slice(&HID_FRAME_HEADER);
            frame.extend_from_slice(&(seq as u16).to_be_bytes());
            frame.extend_from_slice(chunk);
            frame.resize(1 + HID_FRAME_SIZE, 0);
            device
                .write(&frame)
                .map_err(|e| transport_err(format!("ledger: hid write: {e}")))?;
        }

        // Stream the reply back in 64-byte frames.
        let mut reply: Vec<u8> = Vec::new();
        let mut total: usize = 0;
        loop {
            let mut frame = [0u8; HID_FRAME_SIZE];
            let n = device
                .read(&mut frame)
                .map_err(|e| transport_err(format!("ledger: hid read: {e}")))?;
            if n < 7 {
                return Err(transport_err("ledger: short hid frame"));
            }
            if frame[..3] != HID_FRAME_HEADER {
                return Err(transport_err("ledger: invalid reply header"));
            }
            let payload = if frame[3] == 0 && frame[4] == 0 {
                total = u16::from_be_bytes([frame[5], frame[6]]) as usize;
                &frame[7..]
            } else {
                &frame[5..]
            };
            let left = total - reply.len();
            if left > payload.len() {
                reply.extend_from_slice(payload);
            } else {
                reply.extend_from_slice(&payload[..left]);
                break;
            }
        }

        // Split off and check the trailing status word (geth strips it
        // unchecked; checking it here surfaces classifiable errors).
        if reply.len() < 2 {
            return Err(transport_err("ledger: reply lacks status word"));
        }
        let sw = u16::from_be_bytes([reply[reply.len() - 2], reply[reply.len() - 1]]);
        reply.truncate(reply.len() - 2);
        if sw != SW_OK {
            return Err(transport_err(format!("ledger: apdu status {sw:04x}")));
        }
        Ok(reply)
    }
}

/// The default derivation path serialized for an APDU payload: count byte
/// followed by 4-byte big-endian components (hardened bit included).
fn derivation_path_bytes() -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 * DEFAULT_DERIVATION_PATH.len());
    out.push(DEFAULT_DERIVATION_PATH.len() as u8);
    for component in DEFAULT_DERIVATION_PATH {
        out.extend_from_slice(&component.to_be_bytes());
    }
    out
}

impl LedgerWallet for HidWallet {
    fn url(&self) -> String {
        format!("ledger://{}", self.path.to_string_lossy())
    }

    /// Claims the HID handle. Ledger devices take no passphrase at the
    /// transport level; app-presence checks happen in `status`.
    fn open(&mut self, _passphrase: &str) -> Result<(), LedgerTransportError> {
        let device = self
            .api
            .open_path(&self.path)
            .map_err(|e| transport_err(format!("ledger: hid open: {e}")))?;
        self.device = Some(device);
        Ok(())
    }

    fn close(&mut self) -> Result<(), LedgerTransportError> {
        self.device = None;
        Ok(())
    }

    /// Probes the Ethereum app via APDU get-configuration (geth
    /// `ledgerVersion`). With the app closed the dashboard answers with an
    /// error status (6d00/6e00/...), which the caller classifies as
    /// app-not-open.
    fn status(&self) -> Result<String, LedgerTransportError> {
        let reply = self.exchange(INS_GET_CONFIGURATION, 0, 0, &[])?;
        if reply.len() != 4 {
            return Err(transport_err("ledger: invalid version reply"));
        }
        Ok(format!(
            "Ethereum app v{}.{}.{} online",
            reply[1], reply[2], reply[3]
        ))
    }

    /// Derives the default account's address (geth `ledgerDerive`):
    /// response is pubkey-length || pubkey || address-length || 40 hex
    /// ASCII chars of the address.
    fn derive_default(&mut self) -> Result<[u8; 20], LedgerTransportError> {
        let reply = self.exchange(INS_RETRIEVE_ADDRESS, 0, 0, &derivation_path_bytes())?;

        if reply.is_empty() || reply.len() < 1 + reply[0] as usize {
            return Err(transport_err("ledger: reply lacks public key entry"));
        }
        let rest = &reply[1 + reply[0] as usize..];

        if rest.is_empty() || rest.len() < 1 + rest[0] as usize {
            return Err(transport_err("ledger: reply lacks address entry"));
        }
        let hex_ascii = &rest[1..1 + rest[0] as usize];

        let decoded = hex::decode(hex_ascii)
            .map_err(|e| transport_err(format!("ledger: address decode: {e}")))?;
        let addr: [u8; 20] = decoded
            .try_into()
            .map_err(|_| transport_err("ledger: address length mismatch"))?;
        Ok(addr)
    }

    /// Sends the typed transaction for confirmation and signing (geth
    /// `ledgerSign`, type-2 branch).
    fn sign_tx(
        &self,
        parsed: &ParsedTx,
        nonce: u64,
        gas: u64,
    ) -> Result<LedgerSignature, LedgerTransportError> {
        // Payload = derivation path || full typed signing payload
        // (INCLUDING the 0x02 type byte).
        let mut payload = derivation_path_bytes();
        payload.extend(rlp::eip1559_signing_payload(parsed, nonce, gas));

        let mut reply = Vec::new();
        for (i, chunk) in payload.chunks(APDU_CHUNK).enumerate() {
            let p1 = if i == 0 {
                P1_FIRST_CHUNK
            } else {
                P1_CONT_CHUNK
            };
            reply = self.exchange(INS_SIGN_TRANSACTION, p1, 0, chunk)?;
        }

        // v(1) || r(32) || s(32); v is the y-parity for type-2 txs.
        if reply.len() != 65 {
            return Err(transport_err("ledger: reply lacks signature"));
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&reply[1..33]);
        s.copy_from_slice(&reply[33..65]);
        Ok(LedgerSignature { v: reply[0], r, s })
    }
}
