package cli

import "fmt"

// Redact returns a fixed-format redacted representation of s suitable for error
// messages per architecture §8.1 and PRD §9. Format: "<first prefixLen chars>… (len=N)".
// It is a pure function over stdlib types and serves as the single shared helper
// for redacting secret-bearing values before they can appear in errors, logs, or
// other output (BLS secrets, secp256k1 keys, RPC API keys, passphrases, etc.).
//
// If s is the empty string, Redact returns "(empty)" (no length suffix).
// If len(s) <= prefixLen, Redact returns the entire s followed by " (len=N)";
// the length tag is always present so that the redaction does NOT silently
// include/echo the whole secret (policy documented here per M0.4-6 acceptance
// criteria; a bare short secret would be indistinguishable from a successful
// non-redacted value).
// Otherwise Redact returns the prefixLen prefix + "… (len=N)" using the U+2026
// ellipsis for visual consistency.
func Redact(s string, prefixLen int) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) <= prefixLen {
		return fmt.Sprintf("%s (len=%d)", s, len(s))
	}
	return fmt.Sprintf("%s… (len=%d)", s[:prefixLen], len(s))
}
