package tx

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSafeURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"infura path key", "https://mainnet.infura.io/v3/SECRETKEY", "https://mainnet.infura.io"},
		{"userinfo + query key", "https://user:pass@node.example.com:8545/rpc?apikey=KEY", "https://node.example.com:8545"},
		{"plain host:port", "http://127.0.0.1:8545", "http://127.0.0.1:8545"},
		{"websocket path key", "wss://node.example/ws/SECRET", "wss://node.example"},
		{"no host", "foobar", "[redacted-url]"},
		{"empty", "", "[redacted-url]"},
		{"parse error (bad ipv6)", "http://[::1", "[redacted-url]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := safeURL(tc.in)
			if got != tc.want {
				t.Errorf("safeURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for _, tok := range []string{"SECRET", "KEY", "pass"} {
				if strings.Contains(got, tok) {
					t.Errorf("safeURL(%q) leaked %q: %q", tc.in, tok, got)
				}
			}
		})
	}
}

// TestRedactURLString_RealDialError is the discriminating test: it drives the
// REAL leak channel — a *url.Error from the first RPC call to an unreachable
// HTTP endpoint (ethclient dials HTTP lazily) — then WRAPS it exactly as
// builder.go does (two-%w), which is the shape that reaches the log boundary.
// That wrap freezes the message, so it also proves the redaction works on the
// frozen string (an in-place *url.Error mutation would not).
func TestRedactURLString_RealDialError(t *testing.T) {
	const secret = "SECRETKEY123"
	rawURL := "http://127.0.0.1:1/v3/" + secret

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	c, err := NewEthClient(ctx, rawURL)
	if err != nil {
		// Eager-dial path (unlikely for HTTP): must already be scrubbed.
		if strings.Contains(RedactURLString(err), secret) {
			t.Fatalf("NewEthClient error leaked secret: %q", RedactURLString(err))
		}
		return
	}
	defer c.Close()

	_, gerr := c.SuggestGasTipCap(ctx)
	if gerr == nil {
		t.Fatal("expected SuggestGasTipCap to fail against a closed port")
	}
	wrapped := fmt.Errorf("%w: SuggestGasTipCap: %w", ErrRPCEstimation, gerr) // builder.go's shape
	if !strings.Contains(wrapped.Error(), secret) {
		t.Fatalf("probe assumption broken: wrapped error should contain the secret, got %q", wrapped.Error())
	}

	got := RedactURLString(wrapped)
	if strings.Contains(got, secret) {
		t.Errorf("RedactURLString leaked the secret: %q", got)
	}
	if !strings.Contains(got, "http://127.0.0.1:1") {
		t.Errorf("RedactURLString should keep scheme://host, got %q", got)
	}
}

// TestRedactURLString_PreservesChainAndScrubs verifies redaction of the frozen
// two-%w message AND that the original error's errors.Is chain (exit-code
// classification) is untouched.
func TestRedactURLString_PreservesChainAndScrubs(t *testing.T) {
	const secret = "APIKEYABC"
	urlErr := &url.Error{Op: "Post", URL: "https://mainnet.infura.io/v3/" + secret, Err: errors.New("connection refused")}
	wrapped := fmt.Errorf("%w: SuggestGasTipCap: %w", ErrRPCEstimation, urlErr)

	got := RedactURLString(wrapped)
	if strings.Contains(got, secret) {
		t.Errorf("RedactURLString leaked the secret: %q", got)
	}
	if !strings.Contains(got, "https://mainnet.infura.io") {
		t.Errorf("expected scheme://host retained, got %q", got)
	}
	if !errors.Is(wrapped, ErrRPCEstimation) {
		t.Error("RedactURLString must not disturb the original error's errors.Is chain")
	}
}

func TestRedactURLString_NonURLAndNil(t *testing.T) {
	plain := errors.New("some non-url error with no secret")
	if got := RedactURLString(plain); got != plain.Error() {
		t.Errorf("non-url error should render unchanged, got %q", got)
	}
	if got := RedactURLString(nil); got != "" {
		t.Errorf("nil should render as empty string, got %q", got)
	}
}
