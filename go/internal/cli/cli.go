// Package cli defines the urfave/cli/v3 application, flag schema, and input
// validation for eth-deposit-gen. It converts raw CLI flags into a typed Config
// and invokes the caller-supplied run function only after all validations pass.
package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/keystore"
	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/output"
)

// parallelismMultiplier is the factor by which runtime.NumCPU() is multiplied
// to compute the maximum value accepted for the --parallel flag (and the
// upper bound on the worker pool size). 4 permits modest oversubscription for
// the keystore I/O + BLS signing path per architecture §6.10 (FR-P2-A8 / GO-063).
const parallelismMultiplier = 4

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
	// pubkeys. Valid range: 1 to runtime.NumCPU()*parallelismMultiplier. Default is 1 (sequential).
	// Values <= 0 or > runtime.NumCPU()*parallelismMultiplier are rejected with a usage error (exit code 2).
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

// NewApp constructs and returns a configured *cli.Command. The run callback receives
// a validated Config; it is only invoked when all flags are present and valid.
// Validation errors are returned as cli.Exit errors (exit code 1) so that urfave
// can print them to ErrWriter and exit cleanly.
func NewApp(run func(context.Context, Config) error) *ucli.Command {
	app := &ucli.Command{}
	app.Name = "eth-deposit-gen"
	app.Usage = "Generate Launchpad-compatible deposit_data JSON for existing BLS validator keys"
	app.UsageText = `eth-deposit-gen --keystore-dir DIR --pubkeys HEX[,...] --network NET --output-dir DIR --withdrawal-address ADDR [--passphrase-env VAR]`
	app.Description = `Produces deposit_data-<ts>.json for one or more BLS validator public keys by
signing each deposit message with the BLS key loaded from an EIP-2335 keystore.
Output is byte-for-byte compatible with the official ethereum/staking-deposit-cli.`

	app.CustomRootCommandHelpTemplate = `NAME:
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
			Usage: fmt.Sprintf("Number of concurrent signing workers (1–%d); values ≤0 or >%d are rejected", runtime.NumCPU()*parallelismMultiplier, runtime.NumCPU()*parallelismMultiplier),
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

	app.Action = func(ctx context.Context, cmd *ucli.Command) error {
		// Validation order: network first (per spec), then mainnet ack, then pubkeys,
		// then keystore-dir (directory readability probe), then output-dir.

		// 1. Parse and validate --network (eth-deposit-gen only supports mainnet and hoodi)
		net, err := network.ParseFlag(cmd.String("network"))
		if err != nil {
			return ucli.Exit(fmt.Sprintf("--network: %v", err), 2)
		}
		if net != network.Mainnet && net != network.Hoodi {
			return ucli.Exit(fmt.Sprintf(`--network: %q is not supported by eth-deposit-gen; must be %q or %q`, net, network.Mainnet, network.Hoodi), 2)
		}

		// 1a. Mainnet safety gate: require explicit operator acknowledgement before
		// any signing work begins. This must happen before printBanner and before run().
		mainnetAck := cmd.Bool("i-understand-this-is-mainnet")
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
		pubkeys, err := parsePubkeys(cmd.String("pubkeys"))
		if err != nil {
			return ucli.Exit(fmt.Sprintf("--pubkeys: %v", err), 2)
		}

		// 3. Validate --keystore-dir
		keystoreDir := cmd.String("keystore-dir")
		if err := validateKeystoreDir(keystoreDir); err != nil {
			return ucli.Exit(fmt.Sprintf("--keystore-dir: %v", err), 2)
		}

		// 4. Validate --output-dir
		outputDir := cmd.String("output-dir")
		if err := validateOutputDir(outputDir); err != nil {
			return ucli.Exit(fmt.Sprintf("--output-dir: %v", err), 2)
		}

		// 5. Validate --parallel: must be in [1, runtime.NumCPU()*4].
		parallel := cmd.Int("parallel")
		maxParallel := runtime.NumCPU() * 4
		if parallel <= 0 {
			return ucli.Exit(fmt.Sprintf("--parallel: value %d is invalid; must be >= 1", parallel), 2)
		}
		if parallel > maxParallel {
			return ucli.Exit(fmt.Sprintf("--parallel: value %d exceeds maximum of %d (runtime.NumCPU()*parallelismMultiplier); reduce the value or it will oversubscribe the CPU", parallel, maxParallel), 2)
		}

		cfg := Config{
			KeystoreDir:          keystoreDir,
			Pubkeys:              pubkeys,
			Network:              net,
			OutputDir:            outputDir,
			PassphraseEnv:        cmd.String("passphrase-env"),
			MainnetAck:           mainnetAck,
			DryRun:               cmd.Bool("dry-run"),
			Verbose:              cmd.Bool("verbose"),
			JSONLogs:             cmd.Bool("json-logs"),
			Parallel:             parallel,
			VerifyWithDepositCLI: cmd.Bool("verify-with-deposit-cli"),
			DepositCLIPath:       cmd.String("deposit-cli-path"),
		}

		// 5. Print confirmation banner to stderr before invoking run.
		printBanner(cmd.ErrWriter, cfg)

		return run(ctx, cfg)
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

// --- M2.3-5: orchestration moved here from cmd/eth-deposit-gen/main.go for thin-main convention ---
// cmd/*main.go are now thin (flag parse / NewApp / call / exit only). Tests call the (exported) internal entry points below.
// No new module-public API; all in internal/cli.

// CLIVersion mirrors the staking-deposit-cli release used to derive the golden
// test fixtures. Bump only after golden-file re-validation passes.
const CLIVersion = "2.7.0"

// ErrBLSInit is a sentinel used to detect bls.Init() failures in ExitCodeFor.
// herumi errors have no exported sentinel, so we wrap them with this.
var ErrBLSInit = errors.New("bls init failed")

// ErrMainnetAckRequired is returned by RunWithDeps when cfg.Network is mainnet
// but cfg.MainnetAck is false. The CLI gate in app.Action catches this first for
// CLI callers; this sentinel protects non-CLI callers (integration tests, future
// programmatic APIs) and maps to exit code 2.
var ErrMainnetAckRequired = errors.New("mainnet requires explicit acknowledgement (set Config.MainnetAck = true)")

// ErrDepositCLINotFound is returned when --verify-with-deposit-cli is set but the
// binary named by --deposit-cli-path cannot be found in PATH via exec.LookPath.
// Maps to exit code 2 (user / configuration error: binary not installed).
var ErrDepositCLINotFound = errors.New("deposit CLI binary not found")

// ErrDepositCLIFailed is returned when the external staking-deposit-cli process
// exits with a non-zero status during post-generation verification.
// Maps to exit code 3 (the verification step is a crypto/correctness check).
var ErrDepositCLIFailed = errors.New("deposit CLI verification failed")

// deriveWithdrawalCredential01 derives the 32-byte 0x01-form withdrawal
// credential from a validated EIP-55 (or lowercase) 0x-prefixed 20-byte
// execution-layer address: cred[0] = 0x01; cred[1:12] = 0x00*11; cred[12:32] = addr[20].
// This is the exact layout required by the spec and arch §6.11 / §13.2
// ("derivedFromFlag" path). The input is already validated by M0.4-1 (EIP-55 +
// len + hex); derivation is pure, deterministic, no secrets, no side effects.
// Threaded into deposit.Request so it reaches the generator, Entry, JSON output
// (withdrawal_credentials starts "0x01..."), and on-chain deposit.
func DeriveWithdrawalCredential01(withdrawalAddr string) [32]byte {
	var cred [32]byte
	cred[0] = 0x01
	addr := common.HexToAddress(withdrawalAddr)
	copy(cred[12:], addr[:])
	return cred
}

// pickPassphraseSource returns the appropriate PassphraseSource based on cfg.
// If cfg.PassphraseEnv is non-empty, the source reads from that env var.
// Otherwise it falls back to a TTY prompt written to stderr.
func PickPassphraseSource(cfg Config) keystore.PassphraseSource {
	if cfg.PassphraseEnv != "" {
		return keystore.NewEnvSource(cfg.PassphraseEnv)
	}
	return keystore.NewTermPromptSource(os.Stderr)
}

// pickWriter returns the appropriate output.Writer based on cfg.
// When cfg.DryRun is true, returns a DryRunWriter that writes JSON to w
// (typically os.Stdout); otherwise returns an FSWriter that writes to disk.
func PickWriter(cfg Config, w io.Writer) output.Writer {
	if cfg.DryRun {
		return output.NewDryRunWriter(w)
	}
	return output.NewFSWriter()
}

// Deps holds the injectable dependencies for RunWithDeps. In production these
// are filled with real implementations; in tests they can be replaced with fakes.
type Deps struct {
	// InitBLS initialises the herumi BLS library. In tests a no-op can be used.
	InitBLS func() error

	// Scanner scans a keystore directory and returns a pubkey→path index.
	// It is called once before the per-pubkey loop; no decryption occurs here.
	Scanner func(string, *slog.Logger) (keystore.DirectoryIndex, error)

	// Loader is used to load and decrypt the keystore.
	Loader keystore.KeyLoader

	// NewSigner constructs a BLS signer from a secret.
	NewSigner func(secret []byte) (bls.Signer, error)

	// Verifier is used for self-verification in the deposit generator.
	Verifier bls.Verifier

	// Writer is used to persist the deposit data JSON.
	Writer output.Writer

	// SummaryOut is where the success summary line is written.
	SummaryOut io.Writer

	// ProgressOut is where the per-pubkey progress indicator is written.
	// In production this is os.Stderr; in tests use io.Discard or a bytes.Buffer.
	// If the writer is a *os.File connected to a TTY, a single updating line
	// (using \r) is emitted; otherwise slog.Info events are used (non-TTY / CI).
	ProgressOut io.Writer

	// Logger receives structured debug messages. Set to a discarding logger to
	// suppress all output; set to a text/JSON handler to enable debug logging.
	Logger *slog.Logger

	// VerifyDepositCLI is called after a successful write when cfg.VerifyWithDepositCLI
	// is true. The production implementation shells out to exec.Command; tests inject
	// a stub that returns a fixed error or nil without spawning any process.
	//
	// Invocation: <cliPath> verify --input-file <outputPath>
	// This matches the staking-deposit-cli >= 2.7.0 verify subcommand.
	VerifyDepositCLI func(ctx context.Context, cliPath, outputPath string) error
}

// RunDepositCLIVerify is the production implementation of the verifyDepositCLI dep.
// It first probes whether the binary is available via exec.LookPath; if not found
// and the flag was set, it returns ErrDepositCLINotFound (exit code 2). If the
// external process exits non-zero, it returns ErrDepositCLIFailed (exit code 3)
// with the combined stdout+stderr included in the error message.
//
// Invocation: <cliPath> verify --input-file <outputPath>
// This matches staking-deposit-cli >= 2.7.0. See Issue #18 for rationale.
func RunDepositCLIVerify(ctx context.Context, cliPath, outputPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	full, err := exec.LookPath(cliPath)
	if err != nil {
		return fmt.Errorf("%w: %q not found in PATH: %w", ErrDepositCLINotFound, cliPath, err)
	}
	cmd := exec.CommandContext(ctx, full, "verify", "--input-file", outputPath)
	cmd.Env = SanitizedEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return fmt.Errorf("%w: %s: %w", ErrDepositCLIFailed, string(out), err)
	}
	return nil
}

// SanitizedEnv returns os.Environ() filtered to a fixed allow-list.
// The allow-list (HOME, PATH, LANG) is the minimal set required for
// typical operation of the ethstaker-deposit-cli subprocess. It is
// deliberately small and fixed; new entries are added only when a
// concrete use-case appears and must be documented here.
//
// Rationale (per architecture §8.4): the child must never receive
// ETH_DEPOSIT_TX_PRIVATE_KEY (or custom --private-key-env variants)
// or any keystore passphrase env var (from --passphrase-env or
// internal sources). These would be inherited by default because
// exec.CommandContext leaves cmd.Env==nil. Sanitization at spawn
// time is defense-in-depth even after parent-side Unsetenv (M1.1-5)
// or Zeroize (M1.1-6 / M0.8).
func SanitizedEnv() []string {
	allow := map[string]bool{
		"HOME": true,
		"PATH": true,
		"LANG": true,
	}
	var out []string
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok && allow[k] {
			out = append(out, kv)
		}
	}
	return out
}

// buildLogger constructs a *slog.Logger based on the verbose and jsonLogs flags.
// Output is always written to w (os.Stderr in production, a buffer in tests).
// When verbose is true, the handler level is set to Debug; otherwise Info.
// When jsonLogs is true, slog.NewJSONHandler is used; otherwise slog.NewTextHandler.
func BuildLogger(verbose, jsonLogs bool, w io.Writer) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if jsonLogs {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}

// isTTY reports whether w is an *os.File connected to a terminal.
// Any other writer (bytes.Buffer, io.Discard, a pipe) returns false.
func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// emitProgress writes a progress update for the signing loop.
//
// Behaviour:
//   - Suppressed (caller responsibility) when len(cfg.Pubkeys) <= 5.
//   - cfg.JSONLogs=true: always emits structured slog.Info events — same as
//     non-TTY so log capture in CI is never corrupted by \r-overwrite.
//   - progressOut is a TTY: overwrites the current line via \r; emits a final
//     newline when done==total so the subsequent summary line starts cleanly.
//   - progressOut is not a TTY (pipe, buffer, CI): emits one slog.Info event
//     per 10% of progress and always on the last entry.
func emitProgress(d Deps, cfg Config, done, total int) {
	if cfg.JSONLogs {
		d.Logger.Info("signing progress", "done", done, "total", total)
		return
	}
	if isTTY(d.ProgressOut) {
		_, _ = fmt.Fprintf(d.ProgressOut, "\rsigning: %d/%d", done, total) // ignore: best-effort progress to stderr; terminal write failure is non-fatal
		if done == total {
			_, _ = fmt.Fprintln(d.ProgressOut) // ignore: best-effort newline to stderr
		}
		return
	}
	// Non-TTY: emit at each new 10-percentile boundary and always on the last entry.
	pct := done * 100 / total
	prevPct := (done - 1) * 100 / total
	if pct/10 > prevPct/10 || done == total {
		d.Logger.Info("signing progress", "done", done, "total", total)
	}
}

// productionDeps returns the deps wired with all real implementations.
// The logger field is intentionally set to a discarding logger here; Run()
// overrides it with the cfg-configured logger before calling RunWithDeps.
func ProductionDeps() Deps {
	return Deps{
		InitBLS:          bls.Init,
		Scanner:          keystore.ScanDir,
		Loader:           keystore.NewLoader(),
		NewSigner:        bls.NewSigner,
		Verifier:         bls.DefaultVerifier(),
		Writer:           output.NewFSWriter(),
		SummaryOut:       os.Stderr,
		ProgressOut:      os.Stderr,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		VerifyDepositCLI: RunDepositCLIVerify,
	}
}

// RunWithDeps is the testable core of the generator run. It accepts a Deps struct so tests
// can inject fakes without touching the real BLS or keystore implementations.
// It follows the exact wiring order prescribed by Issue #25.
// (Moved from cmd/eth-deposit-gen/main.go:276 per M2.3-5 + FR-P2-A16 thin-main; existing tests call this entry.)
func RunWithDeps(ctx context.Context, cfg Config, d Deps) error {
	log := d.Logger

	// Step 1: initialise the BLS library (process-global, idempotent).
	log.Debug("bls: initialising library")
	if err := d.InitBLS(); err != nil {
		log.Debug("bls: init failed", "error", err)
		return fmt.Errorf("%w: %w", ErrBLSInit, err)
	}
	log.Debug("bls: library ready")

	// Step 2: resolve network parameters.
	log.Debug("network: looking up params", "network", cfg.Network)
	params, err := network.Lookup(cfg.Network)
	if err != nil {
		return fmt.Errorf("resolve network params %q: %w", cfg.Network, err)
	}
	log.Debug("network: params resolved",
		"network", params.Name,
		"genesis_fork_version", fmt.Sprintf("0x%x", params.GenesisForkVersion))

	// Defense-in-depth: re-verify the mainnet acknowledgement inside the pipeline
	// so that non-CLI callers (integration tests, future programmatic APIs) cannot
	// skip the safety gate by constructing a Config directly. The CLI app.Action
	// fires first for CLI callers and returns before reaching this point.
	if cfg.Network == network.Mainnet && !cfg.MainnetAck {
		log.Debug("mainnet: ack not set, aborting")
		return ErrMainnetAckRequired
	}
	// WithdrawalAddress (EIP-55 validated 0x01 input from --withdrawal-address flag,
	// bound in cli layer per M0.4-1) is received here in the Config load path;
	// derive the 0x01 credential for threading (M0.4-2).
	withdrawalCreds := DeriveWithdrawalCredential01(cfg.WithdrawalAddress)
	if cfg.Network == network.Mainnet {
		log.Debug("mainnet: explicit ack verified")
	}

	// Step 3: scan the keystore directory — no decryption yet.
	log.Debug("keystore: scanning directory", "dir", cfg.KeystoreDir)
	index, err := d.Scanner(cfg.KeystoreDir, log)
	if err != nil {
		log.Debug("keystore: scan failed", "error", err)
		return fmt.Errorf("scan keystore dir: %w", err)
	}
	log.Debug("keystore: directory scanned", "count", len(index))

	pwSrc := PickPassphraseSource(cfg)
	defer pwSrc.Zeroize() // M1.1-6: at RunWithDeps end (covers all returns post-pw creation)
	passphraseSource := "tty"
	if cfg.PassphraseEnv != "" {
		passphraseSource = "env:" + cfg.PassphraseEnv
	}

	// Step 4: process pubkeys concurrently using a bounded worker pool.
	// The pool size defaults to 1 when cfg.Parallel == 0 (Config built outside CLI).
	parallel := cfg.Parallel
	if parallel < 1 {
		parallel = 1
	}

	// workerResult carries the output (or error) from one pubkey processing unit.
	type workerResult struct {
		idx   int
		entry deposit.Entry
		err   error
	}

	// Create a cancellable child context so workers can signal each other on error.
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	// work is pre-filled with pubkey indices; workers drain it.
	work := make(chan int, len(cfg.Pubkeys))
	for i := range cfg.Pubkeys {
		work <- i
	}
	close(work)

	results := make(chan workerResult, len(cfg.Pubkeys))

	var wg sync.WaitGroup
	for w := 0; w < parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				if err := workerCtx.Err(); err != nil {
					results <- workerResult{idx: i, err: err}
					continue
				}
				pk := cfg.Pubkeys[i]
				pkHex := fmt.Sprintf("%x", pk[:])
				log.Debug("deposit: processing pubkey", "pubkey", pkHex)

				keystorePath, ok := index.Lookup(pkHex)
				if !ok {
					results <- workerResult{idx: i, err: fmt.Errorf(
						"no keystore found for pubkey 0x%s in %s: %w",
						pkHex, cfg.KeystoreDir, keystore.ErrKeystoreNotFound)}
					workerCancel()
					continue
				}
				log.Debug("keystore: loading", "pubkey", pkHex, "path", keystorePath, "passphrase_source", passphraseSource)

				key, err := d.Loader.Load(workerCtx, keystorePath, pwSrc)
				if err != nil {
					log.Debug("keystore: load failed", "pubkey", pkHex, "error", err)
					results <- workerResult{idx: i, err: err}
					workerCancel()
					continue
				}
				log.Debug("keystore: loaded", "pubkey", key.PubkeyHex, "secret_len", len(key.Secret))

				signer, err := d.NewSigner(key.Secret)
				key.Zeroize() // zeroize immediately after signer is constructed, even on error path
				if err != nil {
					log.Debug("signer: construction failed", "pubkey", pkHex, "error", err)
					results <- workerResult{idx: i, err: err}
					workerCancel()
					continue
				}
				log.Debug("signer: ready", "pubkey", pkHex)

				gen := deposit.NewGenerator(signer, d.Verifier, params)
				log.Debug("deposit: generating entry", "pubkey", pkHex, "network", cfg.Network)
				e, err := gen.Generate(workerCtx, deposit.Request{
					Network:               cfg.Network,
					Pubkeys:               [][48]byte{pk},
					WithdrawalCredentials: withdrawalCreds,
					AmountGwei:            network.MinDepositAmountGwei,
					DepositCLIVersion:     CLIVersion,
				})
				signer.Zeroize() // M1.1-6: after deposit-data generation step (and on gen err path); Go-side only per ADR-006
				if err != nil {
					log.Debug("deposit: generation failed", "pubkey", pkHex, "error", err)
					results <- workerResult{idx: i, err: err}
					workerCancel()
					continue
				}
				results <- workerResult{idx: i, entry: e[0]}
			}
		}()
	}

	// Close results channel once all workers have finished.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results in an indexed slice to preserve input order.
	entries := make([]deposit.Entry, len(cfg.Pubkeys))
	var firstErr error
	done := 0
	n := len(cfg.Pubkeys)
	for r := range results {
		if r.err != nil {
			// Prefer the first non-Canceled error so that the returned error
			// reflects the root cause rather than the cascading cancellation.
			if firstErr == nil || (errors.Is(firstErr, context.Canceled) && !errors.Is(r.err, context.Canceled)) {
				firstErr = r.err
			}
			workerCancel()
			continue
		}
		entries[r.idx] = r.entry
		done++
		if n > 5 {
			emitProgress(d, cfg, done, n)
		}
	}
	if firstErr != nil {
		return firstErr
	}

	log.Debug("deposit: generation complete", "entry_count", len(entries))

	// Step 5: write the deposit data JSON atomically.
	log.Debug("output: writing deposit data", "output_dir", cfg.OutputDir, "entry_count", len(entries))
	path, sum, err := d.Writer.Write(ctx, cfg.OutputDir, entries, time.Now())
	if err != nil {
		log.Debug("output: write failed", "error", err)
		return err
	}
	log.Debug("output: written", "path", path, "sha256", sum)

	// Step 6: optional cross-check with the user's installed staking-deposit-cli.
	// Skipped in dry-run mode because there is no output file on disk to verify
	// (DryRunWriter returns path="" and the JSON was written to stdout instead).
	if cfg.VerifyWithDepositCLI && !cfg.DryRun {
		log.Debug("verify: running deposit CLI cross-check", "cli_path", cfg.DepositCLIPath, "output_path", path)
		if err := d.VerifyDepositCLI(ctx, cfg.DepositCLIPath, path); err != nil {
			log.Debug("verify: deposit CLI check failed", "error", err)
			return err
		}
		log.Debug("verify: deposit CLI cross-check passed")
	}

	// Success: print the summary line.
	PrintSummary(d.SummaryOut, path, sum, len(entries), cfg.Network)
	return nil
}

// Run is the delegate passed to NewApp (thin wrapper that wires production deps then calls RunWithDeps).
// (Moved/adapted from cmd/eth-deposit-gen/main.go per M2.3-5.)
func Run(ctx context.Context, cfg Config) error {
	d := ProductionDeps()
	d.Writer = PickWriter(cfg, os.Stdout)
	d.Logger = BuildLogger(cfg.Verbose, cfg.JSONLogs, os.Stderr)
	return RunWithDeps(ctx, cfg, d)
}

// printSummary writes the success summary line to w.
// Format: wrote <path> (sha256=<hex>, n=<count>, network=<name>)\n
// When path is empty (DryRunWriter returns ""), the placeholder "<stdout>" is
// used so the summary remains human-readable.
func PrintSummary(w io.Writer, path, sha256hex string, n int, net network.Network) {
	display := path
	if display == "" {
		display = "<stdout>"
	}
	_, _ = fmt.Fprintf(w, "wrote %s (sha256=%s, n=%d, network=%s)\n", display, sha256hex, n, net) // ignore: best-effort summary write; failure does not affect success path
}

// ExitCodeFor maps errors to exit codes per the PRD:
//
//	0 — success (nil)
//	2 — user / configuration errors (bad input, validation)
//	3 — signer / crypto errors (wrong passphrase, BLS failure)
//	4 — user abort (SIGINT/SIGTERM / context.Canceled)
//	1 — fallback for any other error
func ExitCodeFor(err error) int {
	if err == nil {
		return 0
	}

	// Exit code 4: context cancellation (SIGINT/SIGTERM).
	if errors.Is(err, context.Canceled) {
		return 4
	}

	// Exit code 2: user / configuration errors.
	if errors.Is(err, keystore.ErrKeystoreMissing) ||
		errors.Is(err, keystore.ErrKeystoreMalformed) ||
		errors.Is(err, keystore.ErrKeystoreVersion) ||
		errors.Is(err, keystore.ErrKeystoreCipherText) ||
		errors.Is(err, keystore.ErrEnvVarEmpty) ||
		errors.Is(err, keystore.ErrKeystoreNotFound) ||
		errors.Is(err, deposit.ErrPubkeyMismatch) ||
		errors.Is(err, ErrMainnetAckRequired) ||
		errors.Is(err, ErrDepositCLINotFound) {
		return 2
	}
	// CLI validation errors from urfave/cli (ExitCoder with code 2).
	var ec ucli.ExitCoder
	if errors.As(err, &ec) && ec.ExitCode() == 2 {
		return 2
	}
	// Substring fallback for urfave required-flag errors (errRequiredFlags wrapped
	// in MultiError; not an ExitCoder, defaults to 1). Maps "Required flag \"...\" not set"
	// (including for --withdrawal-address) to exit 2. This is the pre-validation
	// pattern for missing required flags (M0.4-1 flag + M0.4-7/M1.5-1).
	if strings.Contains(err.Error(), "Required flag") {
		return 2
	}

	// Exit code 3: crypto / signer errors and external verification failures.
	if errors.Is(err, keystore.ErrWrongPassphrase) ||
		errors.Is(err, deposit.ErrSelfVerifyFailed) ||
		errors.Is(err, ErrBLSInit) ||
		errors.Is(err, bls.ErrSecretZero) ||
		errors.Is(err, ErrDepositCLIFailed) {
		return 3
	}

	// Fallback.
	return 1
}
