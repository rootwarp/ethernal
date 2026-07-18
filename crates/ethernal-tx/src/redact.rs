//! RPC-URL redaction for error messages.
//!
//! Ported from `go/internal/tx/redact.go`, adapted to the Rust error model.
//!
//! Go scrubbed the raw URL out of a rendered error at the *log boundary*
//! (`RedactURLString`), because Go's `*url.Error` freezes the full request URL
//! (path + query, where API keys live) into the message. This port instead
//! redacts *by construction*: every `RpcClientError` / `TxError` carrying a
//! transport detail is built from [`redact_url_in`], so no raw URL is ever
//! stored in an error in the first place. [`safe_url`] provides the
//! `scheme://host[:port]` replacement text.

/// Reduces an RPC endpoint URL to `scheme://host[:port]` for safe display,
/// dropping the path, query, and userinfo — the places an API key is commonly
/// embedded (Infura's `/v3/KEY`, `?apikey=`, `user:pass@`). On a parse failure
/// or a URL with no host it returns a fixed placeholder rather than the raw
/// input, so a malformed value that still contains a secret never leaks.
///
/// Divergence from Go: `url::Url` has no scheme-less parse mode, so Go's
/// `if u.Scheme == "" { return u.Host }` branch is unreachable here — a
/// scheme-less input fails to parse and lands on the `[redacted-url]`
/// placeholder. Both implementations refuse to echo the raw input.
pub fn safe_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) => match u.host_str() {
            Some(host) if !host.is_empty() => match u.port() {
                Some(port) => format!("{}://{}:{}", u.scheme(), host, port),
                None => format!("{}://{}", u.scheme(), host),
            },
            _ => "[redacted-url]".to_string(),
        },
        Err(_) => "[redacted-url]".to_string(),
    }
}

/// Returns `message` with every occurrence of `raw_url` — and of its Go
/// `strconv.Quote`-style quoted form — replaced by [`safe_url`] (respectively
/// the quoted safe form). This is the boundary scrub used when constructing an
/// error from a transport-layer message.
///
/// The quoted-form replacement is load-bearing: a control byte in the URL (a
/// trailing `\n` from an env var / CRLF file, or a mid-string `\t`) makes many
/// renderers escape the URL, so a raw-string replace alone would miss it and
/// leak the key. Replacing the `%q`-quoted form as well as the raw form covers
/// both rendering styles.
pub fn redact_url_in(message: &str, raw_url: &str) -> String {
    if raw_url.is_empty() {
        return message.to_string();
    }
    let safe = safe_url(raw_url);
    // Quoted form first (an escaped URL would otherwise defeat the raw replace).
    let out = message.replace(&go_quote(raw_url), &go_quote(&safe));
    // Then the raw form.
    out.replace(raw_url, &safe)
}

/// Renders `s` the way Go's `strconv.Quote` would: wrapped in double quotes with
/// backslash, quote, and control characters escaped. Only the escapes reachable
/// from an ASCII URL are handled explicitly; other control bytes fall back to
/// `\xHH`. This exists so [`redact_url_in`] can match a URL that a renderer has
/// `%q`-escaped.
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0007}' => out.push_str("\\a"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{000b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Go: TestSafeURL
    #[test]
    fn safe_url_cases() {
        let cases = [
            (
                "infura path key",
                "https://mainnet.infura.io/v3/SECRETKEY",
                "https://mainnet.infura.io",
            ),
            (
                "userinfo + query key",
                "https://user:pass@node.example.com:8545/rpc?apikey=KEY",
                "https://node.example.com:8545",
            ),
            (
                "plain host:port",
                "http://127.0.0.1:8545",
                "http://127.0.0.1:8545",
            ),
            (
                "websocket path key",
                "wss://node.example/ws/SECRET",
                "wss://node.example",
            ),
            ("no host", "foobar", "[redacted-url]"),
            ("empty", "", "[redacted-url]"),
            ("parse error (bad ipv6)", "http://[::1", "[redacted-url]"),
        ];
        for (name, input, want) in cases {
            let got = safe_url(input);
            assert_eq!(got, want, "case {name}: safe_url({input:?})");
            for tok in ["SECRET", "KEY", "pass"] {
                assert!(
                    !got.contains(tok),
                    "case {name}: safe_url({input:?}) leaked {tok:?}: {got:?}"
                );
            }
        }
    }

    // Go: TestRedactURLString_PreservesChainAndScrubs (adapted to redact_url_in).
    // A rendered transport error carrying the full URL must lose the key but keep
    // scheme://host.
    #[test]
    fn redact_url_in_scrubs_raw_form() {
        const SECRET: &str = "APIKEYABC";
        let raw = format!("https://mainnet.infura.io/v3/{SECRET}");
        let message = format!("Post {raw}: connection refused");
        let got = redact_url_in(&message, &raw);
        assert!(!got.contains(SECRET), "leaked the secret: {got:?}");
        assert!(
            got.contains("https://mainnet.infura.io"),
            "expected scheme://host retained: {got:?}"
        );
    }

    // Go: TestRedactURLString_ControlByteInURL (BUG-001 regression guard).
    // A control byte makes a renderer %q-escape the URL; redact_url_in must scrub
    // the quoted form too.
    #[test]
    fn redact_url_in_scrubs_quoted_control_byte_form() {
        const SECRET: &str = "REALKEYSECRET";
        let cases = [
            (
                "trailing newline",
                format!("https://mainnet.infura.io/v3/{SECRET}\n"),
            ),
            (
                "mid-string tab",
                format!("https://mainnet.infura.io/v3/\t{SECRET}"),
            ),
        ];
        for (name, raw) in cases {
            // Simulate a renderer that %q-quotes the URL (as Go's url.Error does).
            let message = format!("Post {}: connection refused", go_quote(&raw));
            assert!(
                message.contains(SECRET),
                "case {name}: precondition — quoted message should carry the secret: {message:?}"
            );
            let got = redact_url_in(&message, &raw);
            assert!(
                !got.contains(SECRET),
                "case {name}: control byte defeated redaction: {got:?}"
            );
        }
    }

    // Go: TestRedactURLString_NonURLAndNil (nil arm → empty-URL arm here).
    #[test]
    fn redact_url_in_non_matching_and_empty() {
        let plain = "some non-url error with no secret";
        assert_eq!(redact_url_in(plain, "https://host/x"), plain);
        // Empty raw_url is a no-op (there is nothing to scrub).
        assert_eq!(redact_url_in(plain, ""), plain);
    }
}
