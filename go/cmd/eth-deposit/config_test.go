package main

import (
	"context"
	"math/big"
	"os"
	"testing"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/network"
)

// captureConfig builds a test app with buildCommand() and swaps the Action to
// capture the parsed Config without running real build logic. It returns the
// captured config (or nil on error) and any Action-level error.
//
// OsExiter is overridden to prevent ucli.Exit from calling os.Exit in tests.
func captureConfig(t *testing.T, args []string) (*Config, error) {
	t.Helper()

	// Prevent ucli.Exit from calling os.Exit inside tests.
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	var captured *Config
	var actionErr error

	cmd := buildCommand()
	cmd.Action = func(ctx context.Context, c *ucli.Command) error {
		cfg, err := LoadBuildConfig(c)
		captured = cfg
		actionErr = err
		return err
	}

	app := &ucli.Command{
		Name:     "eth-deposit",
		Commands: []*ucli.Command{cmd},
	}
	// suppress usage output in tests
	app.Writer = os.Stderr
	app.ErrWriter = os.Stderr

	_ = app.Run(context.Background(), append([]string{"eth-deposit"}, args...))
	return captured, actionErr
}

func TestLoadBuildConfig_Defaults(t *testing.T) {
	cfg, err := captureConfig(t, []string{"build", "--network", "holesky", "--input-file", "deposit.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("config is nil")
	}
	if cfg.Network != network.Holesky {
		t.Errorf("Network: got %q, want %q", cfg.Network, network.Holesky)
	}
	if cfg.NetworkParams.ChainID != 17000 {
		t.Errorf("ChainID: got %d, want 17000", cfg.NetworkParams.ChainID)
	}
	// GasLimit is 0 at config load when --gas-limit is omitted; the offline
	// branch in buildUnsignedTx restores the 250000 static default downstream
	// (RPC mode leaves it 0 so the node's EstimateGas runs).
	if cfg.GasLimit != 0 {
		t.Errorf("GasLimit: got %d, want 0 (default applied later, not at config load)", cfg.GasLimit)
	}
	if cfg.MaxFeePerGas != nil {
		t.Errorf("MaxFeePerGas: expected nil when not set, got %s", cfg.MaxFeePerGas)
	}
	if cfg.MaxPriorityFeePerGas != nil {
		t.Errorf("MaxPriorityFeePerGas: expected nil when not set, got %s", cfg.MaxPriorityFeePerGas)
	}
	if cfg.Nonce != nil {
		t.Errorf("Nonce: expected nil when not set, got %d", *cfg.Nonce)
	}
	if cfg.Index != 0 {
		t.Errorf("Index: got %d, want 0", cfg.Index)
	}
	if cfg.InputFile != "deposit.json" {
		t.Errorf("InputFile: got %q, want %q", cfg.InputFile, "deposit.json")
	}
	if cfg.OutputFile != "" {
		t.Errorf("OutputFile: expected empty (stdout), got %q", cfg.OutputFile)
	}
}

func TestLoadBuildConfig_EnvVarOverride(t *testing.T) {
	t.Setenv("ETH_DEPOSIT_TX_RPC_URL", "https://env.example.com")

	cfg, err := captureConfig(t, []string{"build", "--network", "holesky", "--input-file", "deposit.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RPCURL != "https://env.example.com" {
		t.Errorf("RPCURL: got %q, want env value", cfg.RPCURL)
	}
}

func TestLoadBuildConfig_FlagBeatsEnvVar(t *testing.T) {
	t.Setenv("ETH_DEPOSIT_TX_RPC_URL", "https://env.example.com")

	cfg, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--rpc-url", "https://flag.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RPCURL != "https://flag.example.com" {
		t.Errorf("RPCURL: flag should beat env var, got %q", cfg.RPCURL)
	}
}

func TestLoadBuildConfig_UnknownNetwork(t *testing.T) {
	_, err := captureConfig(t, []string{"build", "--network", "unknownnet", "--input-file", "deposit.json"})
	if err == nil {
		t.Fatal("expected error for unknown network, got nil")
	}
}

func TestLoadBuildConfig_InvalidMaxFeePerGas(t *testing.T) {
	_, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--max-fee-per-gas", "not-a-number",
	})
	if err == nil {
		t.Fatal("expected error for invalid --max-fee-per-gas, got nil")
	}
}

func TestLoadBuildConfig_InvalidMaxPriorityFeePerGas(t *testing.T) {
	_, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--max-priority-fee-per-gas", "abc",
	})
	if err == nil {
		t.Fatal("expected error for invalid --max-priority-fee-per-gas, got nil")
	}
}

func TestLoadBuildConfig_InvalidNonce(t *testing.T) {
	_, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--nonce", "not-a-number",
	})
	if err == nil {
		t.Fatal("expected error for invalid --nonce, got nil")
	}
}

func TestLoadBuildConfig_AllFlagsSet(t *testing.T) {
	cfg, err := captureConfig(t, []string{
		"build",
		"--network", "sepolia",
		"--input-file", "batch.json",
		"--output", "unsigned.hex",
		"--index", "3",
		"--rpc-url", "https://rpc.sepolia.example.com",
		"--gas-limit", "300000",
		"--max-fee-per-gas", "20000000000",
		"--max-priority-fee-per-gas", "1000000000",
		"--nonce", "42",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Network != network.Sepolia {
		t.Errorf("Network: got %q, want sepolia", cfg.Network)
	}
	if cfg.InputFile != "batch.json" {
		t.Errorf("InputFile: got %q, want batch.json", cfg.InputFile)
	}
	if cfg.OutputFile != "unsigned.hex" {
		t.Errorf("OutputFile: got %q, want unsigned.hex", cfg.OutputFile)
	}
	if cfg.Index != 3 {
		t.Errorf("Index: got %d, want 3", cfg.Index)
	}
	if cfg.RPCURL != "https://rpc.sepolia.example.com" {
		t.Errorf("RPCURL: got %q", cfg.RPCURL)
	}
	if cfg.GasLimit != 300000 {
		t.Errorf("GasLimit: got %d, want 300000", cfg.GasLimit)
	}
	want := new(big.Int).SetInt64(20000000000)
	if cfg.MaxFeePerGas.Cmp(want) != 0 {
		t.Errorf("MaxFeePerGas: got %s, want %s", cfg.MaxFeePerGas, want)
	}
	wantPrio := new(big.Int).SetInt64(1000000000)
	if cfg.MaxPriorityFeePerGas.Cmp(wantPrio) != 0 {
		t.Errorf("MaxPriorityFeePerGas: got %s, want %s", cfg.MaxPriorityFeePerGas, wantPrio)
	}
	var nonce42 uint64 = 42
	if cfg.Nonce == nil || *cfg.Nonce != nonce42 {
		t.Errorf("Nonce: got %v, want 42", cfg.Nonce)
	}
}

func TestLoadBuildConfig_GasLimitEnvVar(t *testing.T) {
	t.Setenv("ETH_DEPOSIT_TX_GAS_LIMIT", "500000")

	cfg, err := captureConfig(t, []string{"build", "--network", "holesky", "--input-file", "deposit.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.GasLimit != 500000 {
		t.Errorf("GasLimit: expected env override 500000, got %d", cfg.GasLimit)
	}
}

func TestLoadBuildConfig_GasLimitZero(t *testing.T) {
	_, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--gas-limit", "0",
	})
	if err == nil {
		t.Fatal("expected error for --gas-limit=0, got nil")
	}
}

func TestLoadBuildConfig_NegativeMaxFeePerGas(t *testing.T) {
	_, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--max-fee-per-gas", "-100",
	})
	if err == nil {
		t.Fatal("expected error for --max-fee-per-gas=-100, got nil")
	}
}

func TestLoadBuildConfig_NegativeMaxPriorityFeePerGas(t *testing.T) {
	_, err := captureConfig(t, []string{
		"build", "--network", "holesky", "--input-file", "deposit.json",
		"--max-priority-fee-per-gas", "-1",
	})
	if err == nil {
		t.Fatal("expected error for --max-priority-fee-per-gas=-1, got nil")
	}
}

// TestLoadBuildConfig_MissingFlag_Exit2 (M1.5-1 AC): omitting a required flag
// (here --input-file, the only one enforced via pre-validation in LoadBuildConfig)
// produces exit code 2 via the ucli.Exit returned from pre-val (not via urfave's
// internal errRequiredFlags). captureConfig exercises the full parse+Load path.
// (LoadRunConfig delegates to LoadBuildConfig, so this also covers run's missing
// --input-file case for delegation depth; per review, no new explicit run test added.)
func TestLoadBuildConfig_MissingFlag_Exit2(t *testing.T) {
	_, err := captureConfig(t, []string{"build", "--network", "holesky"})
	if err == nil {
		t.Fatal("expected error for missing --input-file, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("ExitCodeFor(missing required via LoadBuildConfig) = %d, want 2", got)
	}
}
