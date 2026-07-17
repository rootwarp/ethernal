//! Minimal RLP encoder for EIP-1559 (type-2) transactions.
//!
//! The Go implementation delegated to go-ethereum (`types.NewTx` +
//! `MarshalBinary` / the signer's `sigHash`); this module hand-rolls the
//! two encodings the signer needs, byte-identical to geth:
//!
//! - the signing payload: `0x02 || rlp([chainId, nonce, tip, maxFee, gas,
//!   to, value, data, accessList])` with an always-empty access list;
//! - the signed envelope: the same list extended with `[yParity, r, s]`.
//!
//! Integers (including y-parity, r and s) are encoded as minimal
//! big-endian byte strings — zero is the empty string, leading zero bytes
//! are stripped.

use crate::parse::ParsedTx;

/// Encodes an RLP byte string.
pub(crate) fn encode_str(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return vec![b[0]];
    }
    let mut out = header(0x80, 0xb7, b.len());
    out.extend_from_slice(b);
    out
}

/// Encodes an RLP list whose `payload` is the concatenation of the
/// already-encoded items.
pub(crate) fn encode_list(payload: &[u8]) -> Vec<u8> {
    let mut out = header(0xc0, 0xf7, payload.len());
    out.extend_from_slice(payload);
    out
}

/// Minimal big-endian representation of an unsigned integer; zero is the
/// empty byte string.
pub(crate) fn uint_be(v: u128) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

/// Strips leading zero bytes (for r/s scalars).
fn trim_leading_zeros(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[first..]
}

fn header(short_base: u8, long_base: u8, len: usize) -> Vec<u8> {
    if len <= 55 {
        vec![short_base + len as u8]
    } else {
        let len_be = uint_be(len as u128);
        let mut out = vec![long_base + len_be.len() as u8];
        out.extend_from_slice(&len_be);
        out
    }
}

/// The nine RLP items common to the signing payload and the signed
/// envelope, concatenated: chainId, nonce, tip, maxFee, gas, to, value,
/// data, and the (always empty) access list.
fn base_fields(p: &ParsedTx, nonce: u64, gas: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(encode_str(&uint_be(u128::from(p.chain_id))));
    buf.extend(encode_str(&uint_be(u128::from(nonce))));
    buf.extend(encode_str(&uint_be(p.tip)));
    buf.extend(encode_str(&uint_be(p.max_fee)));
    buf.extend(encode_str(&uint_be(u128::from(gas))));
    buf.extend(encode_str(&p.to));
    buf.extend(encode_str(&uint_be(p.value)));
    buf.extend(encode_str(&p.data));
    buf.extend(encode_list(&[])); // empty access list
    buf
}

/// The EIP-2718 typed signing payload whose Keccak-256 is the sig-hash:
/// `0x02 || rlp([chainId, nonce, tip, maxFee, gas, to, value, data, []])`.
pub(crate) fn eip1559_signing_payload(p: &ParsedTx, nonce: u64, gas: u64) -> Vec<u8> {
    let mut out = vec![0x02];
    out.extend(encode_list(&base_fields(p, nonce, gas)));
    out
}

/// The signed EIP-2718 envelope accepted by `eth_sendRawTransaction`:
/// `0x02 || rlp([chainId, nonce, tip, maxFee, gas, to, value, data, [],
/// yParity, r, s])`. `r`/`s` are encoded minimally (leading zeros
/// stripped), matching geth's `MarshalBinary`.
pub(crate) fn eip1559_envelope(
    p: &ParsedTx,
    nonce: u64,
    gas: u64,
    y_parity: u8,
    r: &[u8],
    s: &[u8],
) -> Vec<u8> {
    let mut fields = base_fields(p, nonce, gas);
    fields.extend(encode_str(&uint_be(u128::from(y_parity))));
    fields.extend(encode_str(trim_leading_zeros(r)));
    fields.extend(encode_str(trim_leading_zeros(s)));
    let mut out = vec![0x02];
    out.extend(encode_list(&fields));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_str_empty() {
        assert_eq!(encode_str(&[]), vec![0x80]);
    }

    #[test]
    fn encode_str_single_byte_below_0x80() {
        assert_eq!(encode_str(&[0x00]), vec![0x00]);
        assert_eq!(encode_str(&[0x0f]), vec![0x0f]);
        assert_eq!(encode_str(&[0x7f]), vec![0x7f]);
    }

    #[test]
    fn encode_str_single_byte_0x80_gets_prefix() {
        assert_eq!(encode_str(&[0x80]), vec![0x81, 0x80]);
    }

    #[test]
    fn encode_str_dog() {
        assert_eq!(encode_str(b"dog"), vec![0x83, b'd', b'o', b'g']);
    }

    #[test]
    fn encode_str_55_byte_boundary() {
        let b = [0xaau8; 55];
        let enc = encode_str(&b);
        assert_eq!(enc[0], 0x80 + 55); // 0xb7
        assert_eq!(&enc[1..], &b[..]);
        assert_eq!(enc.len(), 56);
    }

    #[test]
    fn encode_str_56_byte_boundary() {
        let b = [0xaau8; 56];
        let enc = encode_str(&b);
        assert_eq!(enc[0], 0xb8);
        assert_eq!(enc[1], 56);
        assert_eq!(&enc[2..], &b[..]);
    }

    #[test]
    fn encode_str_1024_bytes() {
        let b = vec![0x11u8; 1024];
        let enc = encode_str(&b);
        assert_eq!(&enc[..3], &[0xb9, 0x04, 0x00]);
        assert_eq!(enc.len(), 3 + 1024);
    }

    #[test]
    fn encode_list_empty() {
        assert_eq!(encode_list(&[]), vec![0xc0]);
    }

    // The canonical RLP "set theoretical representation of three":
    // [ [], [[]], [ [], [[]] ] ] → c7 c0 c1 c0 c3 c0 c1 c0
    #[test]
    fn encode_list_nested() {
        let empty = encode_list(&[]); // c0
        let one = encode_list(&empty); // c1 c0
        let mut inner = Vec::new();
        inner.extend(&empty);
        inner.extend(&one);
        let two = encode_list(&inner); // c3 c0 c1 c0
        let mut payload = Vec::new();
        payload.extend(&empty);
        payload.extend(&one);
        payload.extend(&two);
        assert_eq!(
            encode_list(&payload),
            vec![0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]
        );
    }

    #[test]
    fn encode_list_long_payload() {
        let payload = vec![0x00u8; 56]; // 56 one-byte items
        let enc = encode_list(&payload);
        assert_eq!(&enc[..2], &[0xf8, 56]);
    }

    #[test]
    fn uint_be_minimal() {
        assert_eq!(uint_be(0), Vec::<u8>::new());
        assert_eq!(uint_be(0x0f), vec![0x0f]);
        assert_eq!(uint_be(0x0400), vec![0x04, 0x00]);
        assert_eq!(uint_be(0xffffffff), vec![0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn encode_uint_zero_is_empty_string() {
        assert_eq!(encode_str(&uint_be(0)), vec![0x80]);
    }

    #[test]
    fn trim_leading_zeros_strips() {
        assert_eq!(trim_leading_zeros(&[0, 0, 1, 2]), &[1, 2]);
        assert_eq!(trim_leading_zeros(&[0, 0]), &[] as &[u8]);
        assert_eq!(trim_leading_zeros(&[9]), &[9]);
    }

    // Field-level check against the committed Holesky golden rawRLP prefix:
    // 0x02 f9021d 824268 80 843b9aca00 8504a817c800 8303d090 94 4242...
    #[test]
    fn signing_payload_field_encoding_matches_golden_prefix() {
        let p = ParsedTx {
            chain_id: 17000,
            value: 0x1bc16d674ec800000,
            max_fee: 0x4a817c800,
            tip: 0x3b9aca00,
            to: [0x42u8; 20],
            data: vec![0u8; 420],
        };
        let payload = eip1559_signing_payload(&p, 0, 250000);
        assert_eq!(payload[0], 0x02);
        // chainId 17000 → 82 42 68; nonce 0 → 80; tip → 84 3b9aca00
        let want_prefix = [
            0x82, 0x42, 0x68, // chainId
            0x80, // nonce
            0x84, 0x3b, 0x9a, 0xca, 0x00, // tip
            0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00, // maxFee
            0x83, 0x03, 0xd0, 0x90, // gas
            0x94, // to header
        ];
        // Skip the type byte and the list header (0xf9 + 2 length bytes).
        assert_eq!(payload[1], 0xf9);
        assert_eq!(&payload[4..4 + want_prefix.len()], &want_prefix);
    }
}
