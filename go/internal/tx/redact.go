package tx

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// safeURL reduces an RPC endpoint URL to scheme://host for safe display,
// dropping the path, query, and userinfo — the places an API key is commonly
// embedded (Infura's /v3/KEY, ?apikey=, user:pass@). It deliberately does NOT
// use url.Redacted, which only masks the userinfo password and leaves
// path/query keys exposed. On a parse failure or a URL with no host it returns
// a fixed placeholder rather than the raw input, so a malformed value that
// still contains a secret never leaks.
func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "[redacted-url]"
	}
	if u.Scheme == "" {
		return u.Host
	}
	return u.Scheme + "://" + u.Host
}

// RedactURLString renders err for logging with any embedded RPC URL reduced to
// scheme://host. It targets the stdlib *url.Error, whose Error() carries the
// full request URL (path and query included) — the channel through which an
// API-key-bearing endpoint leaks: for HTTP(S) URLs ethclient.Dial connects
// lazily, so the failure surfaces on the first RPC call as a *url.Error that
// builder.go then wraps and the process logs at its boundary.
//
// It operates on the string, not the error value, because that wrapping freezes
// the message at fmt.Errorf time — mutating the *url.Error's URL field afterward
// does not change the already-formatted parent. RedactURLString finds the
// *url.Error via errors.As (still reachable in the chain) and replaces every
// occurrence of its raw URL in the rendered message with safeURL. The original
// err is untouched, so the caller's errors.Is/As chain (and exit-code
// classification) is unaffected. nil renders as "".
func RedactURLString(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.URL != "" {
		safe := safeURL(urlErr.URL)
		// url.Error.Error() renders its URL via %q (strconv.Quote), so a control
		// byte in the URL (a trailing \n from an env var / CRLF file, or a mid-
		// string \t) is escaped in the rendered message — the RAW url string then
		// no longer appears and ReplaceAll misses it, leaking the key. Replace the
		// quoted form (load-bearing: url.Error always %q's the URL) and the raw
		// form (harmless belt-and-suspenders for any non-%q rendering).
		s = strings.ReplaceAll(s, strconv.Quote(urlErr.URL), strconv.Quote(safe))
		s = strings.ReplaceAll(s, urlErr.URL, safe)
	}
	return s
}
