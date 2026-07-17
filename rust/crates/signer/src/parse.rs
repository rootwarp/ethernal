//! Decoding of `UnsignedTx` hex fields, ported from
//! `go/internal/signer/parse.go`.

use eth_deposit_tx::UnsignedTx;

use crate::errors::SignerError;

/// Holds the decoded fields of an `UnsignedTx` ready for EIP-1559
/// transaction construction. Wei quantities are `u128` (Go used `*big.Int`;
/// values ≥ 2^128 are rejected as invalid hex — far beyond any real wei
/// amount).
#[derive(Debug)]
pub(crate) struct ParsedTx {
    pub(crate) chain_id: u64,
    pub(crate) value: u128,
    pub(crate) max_fee: u128,
    pub(crate) tip: u128,
    pub(crate) to: [u8; 20],
    pub(crate) data: Vec<u8>,
}

/// Decodes and validates the hex fields of an `UnsignedTx`.
/// Returns the `InvalidChainId` sentinel for zero chain ID; plain format
/// errors for other invalid fields.
pub(crate) fn parse_unsigned_tx(unsigned: &UnsignedTx) -> Result<ParsedTx, SignerError> {
    if unsigned.chain_id == 0 {
        return Err(SignerError::context(
            "ChainID must be non-zero",
            SignerError::InvalidChainId,
        ));
    }

    let value = parse_quantity(&unsigned.value)
        .ok_or_else(|| SignerError::Msg(format!("invalid Value hex {:?}", unsigned.value)))?;

    let max_fee_hex = strip_0x(&unsigned.max_fee_per_gas);
    if max_fee_hex.is_empty() {
        return Err(SignerError::Msg(
            "MaxFeePerGas is required for EIP-1559 transactions".into(),
        ));
    }
    let max_fee = u128::from_str_radix(max_fee_hex, 16).map_err(|_| {
        SignerError::Msg(format!(
            "invalid MaxFeePerGas hex {:?}",
            unsigned.max_fee_per_gas
        ))
    })?;

    let max_prio_hex = strip_0x(&unsigned.max_priority_fee_per_gas);
    if max_prio_hex.is_empty() {
        return Err(SignerError::Msg(
            "MaxPriorityFeePerGas is required for EIP-1559 transactions".into(),
        ));
    }
    let tip = u128::from_str_radix(max_prio_hex, 16).map_err(|_| {
        SignerError::Msg(format!(
            "invalid MaxPriorityFeePerGas hex {:?}",
            unsigned.max_priority_fee_per_gas
        ))
    })?;

    let data_hex = strip_0x(&unsigned.data);
    let data = if data_hex.is_empty() {
        Vec::new()
    } else {
        hex::decode(data_hex).map_err(|e| SignerError::Msg(format!("invalid Data hex: {e}")))?
    };

    Ok(ParsedTx {
        chain_id: unsigned.chain_id,
        value,
        max_fee,
        tip,
        to: hex_to_address(&unsigned.to),
        data,
    })
}

/// Go `strings.TrimPrefix(s, "0x")`: strips at most one lowercase `0x`.
fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// Go `new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)`: `None` on
/// any parse failure (including the empty string).
fn parse_quantity(s: &str) -> Option<u128> {
    u128::from_str_radix(strip_0x(s), 16).ok()
}

/// Mirrors geth's lenient `common.HexToAddress`: strip a `0x`/`0X` prefix,
/// left-pad odd-length input with a `0` nibble, decode hex pairs up to the
/// first invalid character (keeping what decoded so far), then right-align
/// the bytes into 20 bytes, cropping from the left when longer.
pub(crate) fn hex_to_address(s: &str) -> [u8; 20] {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let padded: std::borrow::Cow<'_, str> = if stripped.len() % 2 == 1 {
        format!("0{stripped}").into()
    } else {
        stripped.into()
    };

    // encoding/hex.Decode semantics: stop at the first invalid pair,
    // keeping the prefix decoded so far (geth's Hex2Bytes drops the error).
    let src = padded.as_bytes();
    let mut bytes = Vec::with_capacity(src.len() / 2);
    let mut i = 0;
    while i + 1 < src.len() {
        match (hex_val(src[i]), hex_val(src[i + 1])) {
            (Some(hi), Some(lo)) => bytes.push((hi << 4) | lo),
            _ => break,
        }
        i += 2;
    }

    // geth BytesToAddress: crop left when too long, right-align when short.
    let mut addr = [0u8; 20];
    let tail = if bytes.len() > 20 {
        &bytes[bytes.len() - 20..]
    } else {
        &bytes[..]
    };
    addr[20 - tail.len()..].copy_from_slice(tail);
    addr
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_unsigned() -> UnsignedTx {
        UnsignedTx {
            chain_id: 17000,
            to: "0x4242424242424242424242424242424242424242".into(),
            value: "0x1bc16d674ec800000".into(),
            max_fee_per_gas: "0x4a817c800".into(),
            max_priority_fee_per_gas: "0x3b9aca00".into(),
            gas: 250000,
            tx_type: "0x2".into(),
            ..UnsignedTx::default()
        }
    }

    // Go: TestParseUnsignedTx_InvalidValue (local_internal_test.go)
    #[test]
    fn parse_unsigned_tx_invalid_value() {
        let mut unsigned = base_unsigned();
        unsigned.value = "0xgg".into();
        let err = parse_unsigned_tx(&unsigned).unwrap_err();
        assert_eq!(err.to_string(), "invalid Value hex \"0xgg\"");
    }

    // Go: TestParseUnsignedTx_InvalidData (local_internal_test.go)
    #[test]
    fn parse_unsigned_tx_invalid_data() {
        let mut unsigned = base_unsigned();
        unsigned.data = "0xnotvalidhex".into();
        assert!(parse_unsigned_tx(&unsigned).is_err());
    }

    #[test]
    fn parse_unsigned_tx_chain_id_zero() {
        let mut unsigned = base_unsigned();
        unsigned.chain_id = 0;
        let err = parse_unsigned_tx(&unsigned).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::InvalidChainId));
        assert_eq!(
            err.to_string(),
            "ChainID must be non-zero: invalid chain ID"
        );
    }

    #[test]
    fn parse_unsigned_tx_empty_max_fee() {
        let mut unsigned = base_unsigned();
        unsigned.max_fee_per_gas = String::new();
        let err = parse_unsigned_tx(&unsigned).unwrap_err();
        assert_eq!(
            err.to_string(),
            "MaxFeePerGas is required for EIP-1559 transactions"
        );
    }

    #[test]
    fn parse_unsigned_tx_empty_max_priority_fee() {
        let mut unsigned = base_unsigned();
        unsigned.max_priority_fee_per_gas = String::new();
        let err = parse_unsigned_tx(&unsigned).unwrap_err();
        assert_eq!(
            err.to_string(),
            "MaxPriorityFeePerGas is required for EIP-1559 transactions"
        );
    }

    #[test]
    fn parse_unsigned_tx_valid_fields() {
        let p = parse_unsigned_tx(&base_unsigned()).unwrap();
        assert_eq!(p.chain_id, 17000);
        assert_eq!(p.value, 0x1bc16d674ec800000);
        assert_eq!(p.max_fee, 0x4a817c800);
        assert_eq!(p.tip, 0x3b9aca00);
        assert_eq!(p.to, [0x42u8; 20]);
        assert!(p.data.is_empty());
    }

    // geth common.HexToAddress leniency: short input is right-aligned.
    #[test]
    fn hex_to_address_short_input_right_aligned() {
        let mut want = [0u8; 20];
        want[18] = 0x12;
        want[19] = 0x34;
        assert_eq!(hex_to_address("0x1234"), want);
    }

    // geth common.HexToAddress leniency: odd length gets a leading 0 nibble.
    #[test]
    fn hex_to_address_odd_length() {
        let mut want = [0u8; 20];
        want[19] = 0x01;
        assert_eq!(hex_to_address("0x1"), want);
    }

    // geth common.HexToAddress leniency: >20 bytes is cropped from the left.
    #[test]
    fn hex_to_address_long_input_cropped_left() {
        let long = format!("0xff{}", "42".repeat(20));
        assert_eq!(hex_to_address(&long), [0x42u8; 20]);
    }

    // geth common.HexToAddress leniency: invalid hex keeps the valid prefix.
    #[test]
    fn hex_to_address_invalid_suffix_keeps_prefix() {
        let mut want = [0u8; 20];
        want[19] = 0x12;
        assert_eq!(hex_to_address("0x12zz"), want);
    }
}
