package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	ucli "github.com/urfave/cli/v3"

	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// TestBuild_RPCErrorURLRedactedAtBoundary drives the REAL build path (no mock:
// actual dial to a closed port with a path-embedded secret) and asserts the
// string main.go's boundary logs (internaltx.RedactURLString) carries no secret.
// This pins that the error shape builder.go actually produces stays redactable —
// the integration counterpart to the internal/tx unit tests.
func TestBuild_RPCErrorURLRedactedAtBoundary(t *testing.T) {
	const secret = "INTEGRATIONSECRET"

	cfg, raw := holeskyBuildInputs(t)
	cfg.RPCURL = "http://127.0.0.1:1/v3/" + secret
	cfg.From = testFrom // funded sender so estimation proceeds to the (failing) call

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := buildUnsignedTx(ctx, cfg, raw)
	if err == nil {
		t.Fatal("expected an RPC error against a closed port")
	}

	// The raw error must contain the secret (proves the leak channel is live and
	// the test is meaningful); the boundary-rendered string must not.
	if !strings.Contains(err.Error(), secret) {
		t.Fatalf("precondition: raw error should carry the secret, got %q", err.Error())
	}
	logged := internaltx.RedactURLString(err) // exactly what main.go:85 logs
	if strings.Contains(logged, secret) {
		t.Errorf("boundary redaction leaked the secret: %q", logged)
	}
	if !strings.Contains(logged, "http://127.0.0.1:1") {
		t.Errorf("expected scheme://host retained in logged string, got %q", logged)
	}
}

// TestSend_RPCErrorURLRedactedAtBoundary is the send-path counterpart: a real
// broadcast to a closed port with a secret in the URL fails at BroadcasterChainID
// (a lazy-dialed HTTP call), producing the *url.Error that send.go wraps. It
// guards the send.go/rpc_client.go %w wraps — with %v the URL would be baked out
// of the chain and RedactURLString could not scrub it.
func TestSend_RPCErrorURLRedactedAtBoundary(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	const secret = "SENDINTEGRATIONSECRET"

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://127.0.0.1:1/v3/" + secret,
		"--yes",
	})
	if err == nil {
		t.Fatal("expected a broadcast error against a closed port")
	}
	if !strings.Contains(err.Error(), secret) {
		t.Fatalf("precondition: raw send error should carry the secret, got %q", err.Error())
	}
	logged := internaltx.RedactURLString(err) // what main.go:85 logs
	if strings.Contains(logged, secret) {
		t.Errorf("send boundary redaction leaked the secret: %q", logged)
	}
	if !strings.Contains(logged, "http://127.0.0.1:1") {
		t.Errorf("expected scheme://host retained, got %q", logged)
	}
}
