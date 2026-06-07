// Package cli defines the urfave/cli/v2 application, flag schema, and input
// validation for eth-deposit-gen. It converts raw CLI flags into a typed Config
// and invokes the caller-supplied run function only after all validations pass.
package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/network"
)

// Config holds the validated, parsed inputs from the CLI flags.
type Config struct {
	// KeystoreDir is the filesystem path to the directory containing EIP-2335 JSON keystore files.
	KeystoreDir string

	// Pubkeys is the decoded list of 48-byte BLS12-381 G1 compressed points.
	Pubkeys [][48]byte

	// Network identifies the Ethereum consensus network (mainnet or hoodi).
	Network network.Network

	// OutputDir is the validated, writable directory for deposit_data-<ts>.json.
	OutputDir string

	// WithdrawalAddress is the EIP-55 checksummed 20-byte hex address (0x + 40
	// chars) supplied via the required --withdrawal-address flag (M0.4-1). It is
	// validated (IsHexAddress + exact len 42 + post-check addr.Hex() == input for
	// checksum) before Config is constructed. Per arch §6.11 this is the input
	// for 0x01 credentials; the 0x00 BLS form is absent in v0.2.
	WithdrawalAddress string

	// PassphraseEnv is the name of the environment variable holding the keystore
	// passphrase. An empty string means the tool will fall back to a TTY prompt.
	PassphraseEnv string

	// MainnetAck is true when the operator passed --i-understand-this-is-mainnet,
	// explicitly acknowledging that mainnet deposit data has irreversible financial
	// consequences. Required when Network == network.Mainnet.
	//
	// NOTE: this field may be true for non-mainnet networks if the flag was supplied.
	// Always evaluate it in conjunction with Network == network.Mainnet. The mainnet
	// safety gate is enforced at the CLI layer (before Config is built) and as a
	// defense-in-depth check inside runWithDeps.
	MainnetAck bool

	// DryRun is true when --dry-run is passed. When set, the tool writes JSON to
	// stdout instead of creating a file on disk. The output-dir is validated but
	// nothing is written there. The summary line and sha256 still print to stderr.
	DryRun bool

	// Verbose enables debug-level log output when true. Default is false (Info level).
	Verbose bool

	// JSONLogs selects the JSON log handler when true. Default is false (text handler).
	JSONLogs bool

	// Parallel is the number of concurrent worker goroutines used to process
	// pubkeys. Valid range: 1 to runtime.NumCPU()*4. Default is 1 (sequential).
	// Values <= 0 or > runtime.NumCPU()*4 are rejected with a usage error (exit code 2).
	Parallel int
	// VerifyWithDepositCLI enables optional post-generation cross-check by shelling
	// out to the user's installed staking-deposit-cli. Off by default; opt-in via
	// --verify-with-deposit-cli. Skipped when DryRun is true (no output file exists).
	VerifyWithDepositCLI bool

	// DepositCLIPath is the name or path of the staking-deposit-cli binary to invoke
	// for post-generation verification. Defaults to "deposit". Only used when
	// VerifyWithDepositCLI is true.
	//
	// Minimum supported staking-deposit-cli version: 2.7.0 (same as CLIVersion in main.go).
	DepositCLIPath string
}

// NewApp constructs and returns a configured *cli.App. The run callback receives
// a validated Config; it is only invoked when all flags are present and valid.
// Validation errors are returned as cli.Exit errors (exit code 2, per PRD for
// user/configuration errors) so that urfave can print them to ErrWriter and exit cleanly.
func NewApp(run func(context.Context, Config) error) *ucli.App {
	app := ucli.NewApp()
	app.Name = "eth-deposit-gen"
	app.Usage = "Generate Launchpad-compatible deposit_data JSON for existing BLS validator keys"
	app.UsageText = `eth-deposit-gen --keystore-dir DIR --pubkeys HEX[,...] --network NET --output-dir DIR --withdrawal-address ADDR [--passphrase-env VAR]`
	app.Description = `Produces deposit_data-<ts>.json for one or more BLS validator public keys by
signing each deposit message with the BLS key loaded from an EIP-2335 keystore.
Output is byte-for-byte compatible with the official ethereum/staking-deposit-cli.`

	app.CustomAppHelpTemplate = `NAME:
   {{.Name}} - {{.Usage}}

USAGE:
   {{.UsageText}}

DESCRIPTION:
   {{.Description}}

EXAMPLES:
   # Hoodi testnet, two pubkeys (keystores directory contains one .json per validator)
   eth-deposit-gen \
     --network hoodi \
     --keystore-dir ./keystores/ \
     --pubkeys 0x93247f2209abcafd...,0xa1b2c3d4e5f6... \
     --output-dir ./out \
     --withdrawal-address 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed

   # Mainnet, single pubkey (requires explicit acknowledgement)
   eth-deposit-gen \
     --network mainnet \
     --i-understand-this-is-mainnet \
     --keystore-dir ./keystores/ \
     --pubkeys 0x93247f2209abcafd... \
     --output-dir ./out \
     --withdrawal-address 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}
`

	app.Flags = []ucli.Flag{
		&ucli.StringFlag{
			Name:     "keystore-dir",
			Usage:    "Directory containing EIP-2335 JSON keystore files, one per validator (e.g. ./keystores/)",
			Required: true,
		},
		&ucli.StringFlag{
			Name:     "pubkeys",
			Usage:    "Comma-separated BLS public keys in 96-hex-char form (0x-prefixed or bare)",
			Required: true,
		},
		&ucli.StringFlag{
			Name:     "network",
			Usage:    `Ethereum consensus network: "mainnet" or "hoodi"`,
			Required: true,
		},
		&ucli.StringFlag{
			Name:     "output-dir",
			Usage:    "Existing, writable directory for the output deposit_data-<ts>.json file",
			Required: true,
		},
		&ucli.StringFlag{
			Name:  "withdrawal-address",
			Usage: "Required EIP-55 checksummed (or all-lower) 0x-prefixed 20-byte execution address used to derive 0x01 withdrawal credential (e.g. 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed). Prevents all-zero 0x00 credential (GO-001).",
			// Required omitted deliberately: the presence + EIP-55 guard inside Action returns ucli.Exit(..., 2) (ExitCoder) for reliable cast in tests and consistent pre-val pattern (other Requireds still use urfave + exitCodeFor substring fallback for their missing->2).
		},
		&ucli.StringFlag{
			Name:  "passphrase-env",
			Usage: "Name of the environment variable holding the keystore passphrase (omit for TTY prompt)",
		},
		&ucli.BoolFlag{
			Name:  "i-understand-this-is-mainnet",
			Usage: "Required when --network mainnet: acknowledges this produces REAL mainnet deposit data with irreversible financial consequences",
		},
		&ucli.BoolFlag{
			Name:  "dry-run",
			Usage: "Print the deposit JSON to stdout instead of writing a file to --output-dir; no file is created. The sha256 on stderr matches the bytes written to stdout.",
		},
		&ucli.BoolFlag{
			Name:  "verbose",
			Usage: "Enable debug-level structured logging to stderr",
		},
		&ucli.BoolFlag{
			Name:  "json-logs",
			Usage: "Emit logs as JSON objects instead of human-readable text",
		},
		&ucli.IntFlag{
			Name:  "parallel",
			Usage: fmt.Sprintf("Number of concurrent signing workers (1–%d); values ≤0 or >%d are rejected", runtime.NumCPU()*4, runtime.NumCPU()*4),
			Value: 1,
		},
		&ucli.BoolFlag{
			Name: "verify-with-deposit-cli",
			Usage: "After writing the deposit JSON, run the installed staking-deposit-cli to cross-check " +
				"the output file (requires staking-deposit-cli >= 2.7.0; see --deposit-cli-path). " +
				"Skipped in --dry-run mode. Off by default.",
		},
		&ucli.StringFlag{
			Name:  "deposit-cli-path",
			Value: "deposit",
			Usage: "Name or absolute path of the staking-deposit-cli binary used for --verify-with-deposit-cli " +
				"(minimum supported version: 2.7.0). Defaults to \"deposit\" (looked up in PATH).",
		},
	}

	app.Action = func(c *ucli.Context) error {
		// Validation order: network first (per spec), then mainnet ack, then
		// --withdrawal-address (M0.4-1 EIP-55 guard), then pubkeys, then
		// keystore-dir (directory readability probe), then output-dir.

		// 1. Parse and validate --network (eth-deposit-gen only supports mainnet and hoodi)
		net, err := network.ParseFlag(c.String("network"))
		if err != nil {
			return ucli.Exit(fmt.Sprintf("--network: %v", err), 2)
		}
		if net != network.Mainnet && net != network.Hoodi {
			return ucli.Exit(fmt.Sprintf(`--network: %q is not supported by eth-deposit-gen; must be %q or %q`, net, network.Mainnet, network.Hoodi), 2)
		}

		// 1a. Mainnet safety gate: require explicit operator acknowledgement before
		// any signing work begins. This must happen before printBanner and before run().
		mainnetAck := c.Bool("i-understand-this-is-mainnet")
		if net == network.Mainnet && !mainnetAck {
			return ucli.Exit("mainnet selected; pass --i-understand-this-is-mainnet to acknowledge", 2)
		}

		// 1b. Validate --withdrawal-address (M0.4-1, closes flag-layer of GO-001).
		// Enforces at the CLI input boundary: exact 42 chars (0x + 40 hex), IsHexAddress
		// (valid hex, any case), and EIP-55 checksum only when the supplied value uses
		// mixed case (all-lower and all-upper valid-hex forms are accepted as "no
		// checksum claim"). On any failure: clear operator guidance + exit 2; no
		// deposit is produced. The validated string is bound to Config and will be
		// used (M0.4-2) to derive 0x01 || 0x00*11 || addr[20]. This is prerequisite
		// to safely deleting the dangerous default placeholder logic (M0.4-3).
		withdrawalAddr := c.String("withdrawal-address")
		if len(withdrawalAddr) != 42 {
			return ucli.Exit(fmt.Sprintf("--withdrawal-address: has invalid length %d (want 42)", len(withdrawalAddr)), 2)
		}
		if !common.IsHexAddress(withdrawalAddr) {
			return ucli.Exit("--withdrawal-address: contains non-hex characters (after 0x prefix)", 2)
		}
		// Normalize 0X prefix (IsHex accepts it; .Hex() always uses 0x) so that
		// 0X + correct EIP55 mixed-case letters is accepted (not falsely treated as mismatch).
		norm := withdrawalAddr
		if strings.HasPrefix(norm, "0X") {
			norm = "0x" + norm[2:]
		}
		if norm != strings.ToLower(norm) && norm != strings.ToUpper(norm) {
			if common.HexToAddress(withdrawalAddr).Hex() != norm {
				return ucli.Exit("--withdrawal-address: EIP-55 checksum mismatch (supply the address in all-lowercase or with correct mixed-case checksum)", 2)
			}
		}

		// 2. Parse and validate --pubkeys
		pubkeys, err := parsePubkeys(c.String("pubkeys"))
		if err != nil {
			return ucli.Exit(fmt.Sprintf("--pubkeys: %v", err), 2)
		}

		// 3. Validate --keystore-dir
		keystoreDir := c.String("keystore-dir")
		if err := validateKeystoreDir(keystoreDir); err != nil {
			return ucli.Exit(fmt.Sprintf("--keystore-dir: %v", err), 2)
		}

		// 4. Validate --output-dir
		outputDir := c.String("output-dir")
		if err := validateOutputDir(outputDir); err != nil {
			return ucli.Exit(fmt.Sprintf("--output-dir: %v", err), 2)
		}

		// 5. Validate --parallel: must be in [1, runtime.NumCPU()*4].
		parallel := c.Int("parallel")
		maxParallel := runtime.NumCPU() * 4
		if parallel <= 0 {
			return ucli.Exit(fmt.Sprintf("--parallel: value %d is invalid; must be >= 1", parallel), 2)
		}
		if parallel > maxParallel {
			return ucli.Exit(fmt.Sprintf("--parallel: value %d exceeds maximum of %d (runtime.NumCPU()*4); reduce the value or it will oversubscribe the CPU", parallel, maxParallel), 2)
		}

		cfg := Config{
			KeystoreDir:          keystoreDir,
			Pubkeys:              pubkeys,
			Network:              net,
			OutputDir:            outputDir,
			PassphraseEnv:        c.String("passphrase-env"),
			MainnetAck:           mainnetAck,
			DryRun:               c.Bool("dry-run"),
			Verbose:              c.Bool("verbose"),
			JSONLogs:             c.Bool("json-logs"),
			Parallel:             parallel,
			VerifyWithDepositCLI: c.Bool("verify-with-deposit-cli"),
			DepositCLIPath:       c.String("deposit-cli-path"),
			WithdrawalAddress:    withdrawalAddr,
		}

		// 5. Print confirmation banner to stderr before invoking run.
		printBanner(c.App.ErrWriter, cfg)

		return run(c.Context, cfg)
	}

	return app
}

// parsePubkeys splits a comma-separated pubkey string, validates each entry,
// and decodes them into [48]byte arrays. It is an unexported function so that
// the fuzz target in cli_fuzz_test.go can call it directly.
//
// Rules:
//   - Split on ',' and trim whitespace per entry.
//   - Accept both 0x-prefixed and unprefixed hex.
//   - Lowercase hex before decoding (hex.DecodeString is case-insensitive but
//     we normalise for consistency).
//   - Reject mixed prefix: all entries must be uniformly prefixed or unprefixed.
//   - Each hex string must decode to exactly 48 bytes (96 hex chars).
func parsePubkeys(s string) ([][48]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("no pubkeys supplied")
	}

	parts := strings.Split(s, ",")
	entries := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			return nil, fmt.Errorf("empty pubkey entry in list")
		}
		entries = append(entries, trimmed)
	}

	// Determine prefix uniformity: inspect the first entry, then check all others match.
	firstHasPrefix := strings.HasPrefix(entries[0], "0x") || strings.HasPrefix(entries[0], "0X")
	for i, e := range entries {
		hasPrefix := strings.HasPrefix(e, "0x") || strings.HasPrefix(e, "0X")
		if hasPrefix != firstHasPrefix {
			return nil, fmt.Errorf("mixed 0x prefix: entry %d %q does not match prefix style of entry 0 %q — all pubkeys must be uniformly prefixed or unprefixed", i, e, entries[0])
		}
	}

	result := make([][48]byte, 0, len(entries))
	for _, e := range entries {
		h := strings.ToLower(e)
		h = strings.TrimPrefix(h, "0x")

		// Validate length: 48 bytes = 96 hex chars.
		if len(h) != 96 {
			return nil, fmt.Errorf("pubkey %q has wrong hex length %d, want 96 (48 bytes)", e, len(h))
		}

		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("pubkey %q is not valid hex: %w", e, err)
		}

		var arr [48]byte
		copy(arr[:], b)

		// Validate the bytes represent a valid compressed G1 point on BLS12-381.
		if err := bls.ValidatePubkeyBytes(arr); err != nil {
			return nil, fmt.Errorf("pubkey %q is not a valid BLS12-381 G1 point: %w", e, err)
		}

		result = append(result, arr)
	}

	return result, nil
}

// validateKeystoreDir checks that dir exists and is a readable directory.
// It probes readability by calling os.ReadDir; any error (non-directory path or
// permission error) is returned as a user error (exit code 2 via the caller).
func validateKeystoreDir(dir string) error {
	if _, err := os.ReadDir(dir); err != nil {
		return fmt.Errorf("cannot read keystore directory %q: %w", dir, err)
	}
	return nil
}

// validateOutputDir checks that dir exists and the process can write to it.
// It probes writability by creating and immediately removing a temporary file.
func validateOutputDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory %q does not exist", dir)
		}
		return fmt.Errorf("cannot stat directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}

	// Probe writability: create a temp file then remove it immediately.
	f, err := os.CreateTemp(dir, ".eth-deposit-gen-probe-*")
	if err != nil {
		return fmt.Errorf("directory %q is not writable: %w", dir, err)
	}
	_ = f.Close()           // ignore: best-effort close on temp probe file (writable dir already proven by create)
	_ = os.Remove(f.Name()) // ignore: best-effort remove on temp probe file (dir writability already proven)
	return nil
}

// networkDisplay returns the network name for display in the banner.
// Mainnet is shown in uppercase ("MAINNET") as an additional visual safety cue;
// all other networks use their lowercase string representation.
func networkDisplay(n network.Network) string {
	if n == network.Mainnet {
		return "MAINNET"
	}
	return string(n)
}

// printBanner writes the confirmation banner to w (which should be app.ErrWriter).
// Format: eth-deposit-gen: network=<net> first_pubkey=<hex> last_pubkey=<hex> count=<n>
// Pubkeys are rendered as 0x-prefixed lowercase hex. Mainnet is shown as "MAINNET".
func printBanner(w io.Writer, cfg Config) {
	if len(cfg.Pubkeys) == 0 {
		return
	}
	first := cfg.Pubkeys[0]
	last := cfg.Pubkeys[len(cfg.Pubkeys)-1]
	_, _ = fmt.Fprintf(w, "eth-deposit-gen: network=%s first_pubkey=0x%x last_pubkey=0x%x count=%d\n",
		networkDisplay(cfg.Network),
		first[:],
		last[:],
		len(cfg.Pubkeys)) // ignore: best-effort banner write to ErrWriter
}

// requireNoArgs returns ucli.Exit(..., 2) if c.NArg() > 0, naming the offending
// positional arg(s) (so the operator sees what was misread, e.g. as a flag value).
// Returns nil for zero positional args. Unexported helper (per CONVENTIONS) for
// call from both CLIs' Actions (architecture §6.10 / research/10 §2).
func requireNoArgs(c *ucli.Context) error {
	if c.NArg() > 0 {
		return ucli.Exit(fmt.Sprintf("unexpected positional argument: %s", c.Args().First()), 2)
	}
	return nil
}
