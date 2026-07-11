package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v3"
)

// --- LoadBuildConfig --from parsing (via captureConfig, config.go:LoadBuildConfig) ---

func TestLoadBuildConfig_FromValid(t *testing.T) {
	const addr = "0x1234567890123456789012345678901234567890"
	cfg, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--from", addr,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, _ := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
	if !bytes.Equal(cfg.From[:], want) {
		t.Errorf("From: got %x, want %x", cfg.From, want)
	}
}

func TestLoadBuildConfig_FromNoPrefix(t *testing.T) {
	const addr = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	cfg, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--from", addr,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, _ := hex.DecodeString(addr)
	if !bytes.Equal(cfg.From[:], want) {
		t.Errorf("From: got %x, want %x", cfg.From, want)
	}
}

func TestLoadBuildConfig_FromUnset(t *testing.T) {
	cfg, err := captureConfig(t, []string{"build", "--network", "holesky", "--input-file", "deposit.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.From != ([20]byte{}) {
		t.Errorf("From: expected zero value when --from unset, got %x", cfg.From)
	}
}

func TestLoadBuildConfig_FromEnvVar(t *testing.T) {
	const addr = "0x00000000219ab540356cbb839cbe05303d7705fa"
	t.Setenv("ETH_DEPOSIT_TX_FROM", addr)

	cfg, err := captureConfig(t, []string{"build", "--network", "holesky", "--input-file", "deposit.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, _ := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
	if !bytes.Equal(cfg.From[:], want) {
		t.Errorf("From: got %x, want env value %x", cfg.From, want)
	}
}

func TestLoadBuildConfig_FromBadHex(t *testing.T) {
	// Non-hex characters — hex.DecodeString fails. common.HexToAddress would
	// silently accept this by ignoring bad nibbles; strict parsing rejects it.
	_, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--from", "0xZZ34567890123456789012345678901234567890",
	})
	if err == nil {
		t.Fatal("expected error for invalid --from hex, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestLoadBuildConfig_FromWrongLength(t *testing.T) {
	// Well-formed hex but not exactly 20 bytes — must be rejected (common.HexToAddress
	// would truncate/pad instead).
	for _, addr := range []string{
		"0x1234", // 2 bytes
		"0x12345678901234567890123456789012345678901234", // 22 bytes
	} {
		_, err := captureConfig(t, []string{
			"build", "--network", "holesky", "--input-file", "deposit.json",
			"--from", addr,
		})
		if err == nil {
			t.Fatalf("expected error for wrong-length --from %q, got nil", addr)
		}
		if got := ExitCodeFor(err); got != 2 {
			t.Errorf("--from %q: exit code = %d, want 2", addr, got)
		}
	}
}

// --- The config-time gate (requireFromForRPC, main.go) ---

// TestRequireFromForRPC exercises the gate condition directly. This covers the
// cfg.GasLimit == 0 (gas-omitted) half, which cannot be produced through the
// build CLI until P2-2 removes LoadBuildConfig's eager gas default — testing the
// helper directly is the honest way to lock in that half now.
func TestRequireFromForRPC(t *testing.T) {
	nonZeroFrom := [20]byte{0x01}
	nonce := func() *uint64 { n := uint64(5); return &n }

	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "offline: no --rpc-url, nothing else set",
			cfg:  Config{},
		},
		{
			name:    "rpc + nonce omitted + from zero -> required (live in P2-1)",
			cfg:     Config{RPCURL: "http://node", GasLimit: 250_000},
			wantErr: true,
		},
		{
			name:    "rpc + gas omitted + nonce set + from zero -> required (P2-2-live half)",
			cfg:     Config{RPCURL: "http://node", GasLimit: 0, Nonce: nonce()},
			wantErr: true,
		},
		{
			name: "rpc + nonce set + gas set + from zero -> not required",
			cfg:  Config{RPCURL: "http://node", GasLimit: 250_000, Nonce: nonce()},
		},
		{
			name: "rpc + from set + nonce omitted -> not required",
			cfg:  Config{RPCURL: "http://node", From: nonZeroFrom, GasLimit: 250_000},
		},
		{
			name: "rpc + from set + gas omitted + nonce set -> not required",
			cfg:  Config{RPCURL: "http://node", From: nonZeroFrom, GasLimit: 0, Nonce: nonce()},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireFromForRPC(&tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if got := ExitCodeFor(err); got != 2 {
					t.Errorf("exit code = %d, want 2; err = %v", got, err)
				}
				if !strings.Contains(err.Error(), "--from") {
					t.Errorf("error should mention --from, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("expected nil error, got: %v", err)
			}
		})
	}
}

// TestBuild_RPCRequiresFromWhenNonceOmitted proves the gate is wired into build's
// Action. A valid fixture is used deliberately: without the gate the build would
// succeed offline (P2-1 does not dial the RPC), so an exit-2 error IS proof the
// gate fired rather than something downstream failing.
func TestBuild_RPCRequiresFromWhenNonceOmitted(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "build",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--rpc-url", "http://127.0.0.1:0",
		// no --from, no --nonce -> gate fires
	})
	if err == nil {
		t.Fatal("expected exit-2 gate error, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
	if !strings.Contains(err.Error(), "--from") {
		t.Errorf("error should mention --from, got: %v", err)
	}
}

// TestBuild_FromNotRequiredWithNonceAndGas confirms that supplying both --nonce
// and --gas-limit lifts the --from requirement even with --rpc-url set. In P2-1
// the RPC is not dialed, so the build completes offline (exit 0).
func TestBuild_FromNotRequiredWithNonceAndGas(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err := app.Run(context.Background(), []string{
		"eth-deposit", "build",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--rpc-url", "http://127.0.0.1:0",
		"--nonce", "7",
		"--gas-limit", "250000",
		// no --from -> not required because both nonce and gas are explicit
	})
	if err != nil {
		t.Fatalf("expected success (--from not required), got: %v", err)
	}
	if out.Len() == 0 {
		t.Error("expected unsigned tx output, got empty")
	}
}

// TestRun_FromUndeclaredIsHarmless confirms the shared LoadBuildConfig parser is
// unaffected for run, which does not declare --from: c.String("from") returns ""
// and From stays zero, with no error.
func TestRun_FromUndeclaredIsHarmless(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	var captured *Config
	var actionErr error

	cmd := runCommand()
	cmd.Action = func(ctx context.Context, c *ucli.Command) error {
		cfg, err := LoadBuildConfig(c) // the first step of LoadRunConfig
		captured = cfg
		actionErr = err
		return err
	}

	app := &ucli.Command{Name: "eth-deposit", Commands: []*ucli.Command{cmd}}
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	_ = app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", "deposit.json",
	})

	if actionErr != nil {
		t.Fatalf("LoadBuildConfig via run errored (should be unaffected by --from): %v", actionErr)
	}
	if captured == nil {
		t.Fatal("config not captured")
	}
	if captured.From != ([20]byte{}) {
		t.Errorf("From: expected zero for run (no --from flag declared), got %x", captured.From)
	}
}
