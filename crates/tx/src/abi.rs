//! ABI encoding of the deposit contract's `deposit()` call.
//!
//! Ported from `go/internal/tx/abi.go`.

/// The 4-byte ABI selector for `deposit(bytes,bytes,bytes,bytes32)`.
/// Derived from Keccak-256("deposit(bytes,bytes,bytes,bytes32)")[:4] = 0x22895118.
/// Verified in the abi tests via a Keccak-256 recomputation.
const DEPOSIT_SELECTOR: [u8; 4] = [0x22, 0x89, 0x51, 0x18];

/// ABI-encodes a call to the deposit contract's `deposit()` function.
///
/// ABI layout (420 bytes total):
///
/// ```text
/// selector (4 bytes) || head (128 bytes) || tail (288 bytes)
/// ```
///
/// Head — 4 slots of 32 bytes each:
///
/// ```text
/// [0] offset_pubkey = 128  (4 head slots × 32 bytes)
/// [1] offset_wc     = 224  (128 + 32 length + 64 padded-pubkey)
/// [2] offset_sig    = 288  (224 + 32 length + 32 wc already 32-byte aligned)
/// [3] deposit_data_root (static bytes32, inline)
/// ```
///
/// Tail:
///
/// ```text
/// uint256(48) || pubkey(48) || pad(16)  — pubkey segment (96 bytes)
/// uint256(32) || wc(32)                 — withdrawal_credentials segment (64 bytes)
/// uint256(96) || sig(96)                — signature segment (128 bytes)
/// ```
pub fn pack_deposit(pubkey: &[u8; 48], wc: &[u8; 32], sig: &[u8; 96], root: &[u8; 32]) -> Vec<u8> {
    let mut buf = vec![0u8; 420];
    let mut pos = 0usize;

    // Selector.
    buf[pos..pos + 4].copy_from_slice(&DEPOSIT_SELECTOR);
    pos += 4;

    // Head slot 0: offset_pubkey = 128.
    put_uint256(&mut buf[pos..pos + 32], 128);
    pos += 32;

    // Head slot 1: offset_wc = 224.
    put_uint256(&mut buf[pos..pos + 32], 224);
    pos += 32;

    // Head slot 2: offset_sig = 288.
    put_uint256(&mut buf[pos..pos + 32], 288);
    pos += 32;

    // Head slot 3: deposit_data_root (static bytes32).
    buf[pos..pos + 32].copy_from_slice(root);
    pos += 32;

    // Tail — pubkey segment: uint256(48) || pubkey(48) || pad(16).
    put_uint256(&mut buf[pos..pos + 32], 48);
    pos += 32;
    buf[pos..pos + 48].copy_from_slice(pubkey);
    pos += 48;
    pos += 16; // zero padding to 64-byte boundary

    // Tail — withdrawal_credentials segment: uint256(32) || wc(32).
    put_uint256(&mut buf[pos..pos + 32], 32);
    pos += 32;
    buf[pos..pos + 32].copy_from_slice(wc);
    pos += 32;

    // Tail — signature segment: uint256(96) || sig(96).
    put_uint256(&mut buf[pos..pos + 32], 96);
    pos += 32;
    buf[pos..pos + 96].copy_from_slice(sig);

    buf
}

/// Writes `v` as a big-endian 32-byte unsigned integer into `b` (which must be
/// exactly 32 bytes). The top 24 bytes are zeroed and the low 8 bytes carry `v`.
fn put_uint256(b: &mut [u8], v: u64) {
    for byte in b.iter_mut().take(24) {
        *byte = 0;
    }
    b[24..32].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    // The canonical function signature for computing the selector.
    const DEPOSIT_SIG: &str = "deposit(bytes,bytes,bytes,bytes32)";

    // The exact byte length of ABI-encoded deposit() calldata.
    // Layout: selector(4) + head(128) + tail(pubkey:32+64 + wc:32+32 + sig:32+96) = 4+128+288 = 420.
    const EXPECTED_CALLDATA_LEN: usize = 420;

    fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(data);
        h.finalize().into()
    }

    fn read_uint256_as_u64(b: &[u8]) -> u64 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&b[24..32]);
        u64::from_be_bytes(arr)
    }

    // Go: TestPackDeposit_SelectorMatchesKeccak256
    #[test]
    fn pack_deposit_selector_matches_keccak256() {
        let got = pack_deposit(&[0u8; 48], &[0u8; 32], &[0u8; 96], &[0u8; 32]);
        let want = keccak256(DEPOSIT_SIG.as_bytes());
        assert_eq!(&got[..4], &want[..4], "selector must match keccak256[:4]");
    }

    // Go: TestPackDeposit_Length
    #[test]
    fn pack_deposit_length() {
        let got = pack_deposit(&[0u8; 48], &[0u8; 32], &[0u8; 96], &[0u8; 32]);
        assert_eq!(got.len(), EXPECTED_CALLDATA_LEN);
    }

    // Go: TestPackDeposit_LengthWithRandomBytes
    #[test]
    fn pack_deposit_length_with_random_bytes() {
        let mut pubkey = [0u8; 48];
        let mut wc = [0u8; 32];
        let mut sig = [0u8; 96];
        let mut root = [0u8; 32];
        for (i, b) in pubkey.iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in wc.iter_mut().enumerate() {
            *b = (i + 100) as u8;
        }
        for (i, b) in sig.iter_mut().enumerate() {
            *b = (i * 2) as u8;
        }
        for (i, b) in root.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }
        let got = pack_deposit(&pubkey, &wc, &sig, &root);
        assert_eq!(got.len(), EXPECTED_CALLDATA_LEN);
    }

    // Go: TestPackDeposit_RoundTrip
    #[test]
    fn pack_deposit_round_trip() {
        let pubkey = [0xaau8; 48];
        let wc = [0xbbu8; 32];
        let sig = [0xccu8; 96];
        let root = [0xeeu8; 32];

        let got = pack_deposit(&pubkey, &wc, &sig, &root);

        // Verify selector.
        assert_eq!(&got[..4], &[0x22, 0x89, 0x51, 0x18], "selector mismatch");

        // Decode head: 4 slots of 32 bytes each.
        let head = &got[4..132];
        let offset_pubkey = read_uint256_as_u64(&head[0..32]);
        let offset_wc = read_uint256_as_u64(&head[32..64]);
        let offset_sig = read_uint256_as_u64(&head[64..96]);
        let got_root = &head[96..128];

        assert_eq!(offset_pubkey, 128, "offsetPubkey");
        assert_eq!(offset_wc, 224, "offsetWC");
        assert_eq!(offset_sig, 288, "offsetSig");
        assert_eq!(got_root, &root, "deposit_data_root");

        // Tail offsets are relative to the start of args (got[4:]).
        let tail = &got[4..];

        let op = offset_pubkey as usize;
        let pubkey_len = read_uint256_as_u64(&tail[op..op + 32]);
        assert_eq!(pubkey_len, 48, "pubkey length");
        assert_eq!(&tail[op + 32..op + 32 + 48], &pubkey, "pubkey");

        let ow = offset_wc as usize;
        let wc_len = read_uint256_as_u64(&tail[ow..ow + 32]);
        assert_eq!(wc_len, 32, "wc length");
        assert_eq!(&tail[ow + 32..ow + 32 + 32], &wc, "wc");

        let os = offset_sig as usize;
        let sig_len = read_uint256_as_u64(&tail[os..os + 32]);
        assert_eq!(sig_len, 96, "sig length");
        assert_eq!(&tail[os + 32..os + 32 + 96], &sig, "sig");
    }
}
