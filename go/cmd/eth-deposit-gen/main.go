// Package main is the entry point for eth-deposit-gen. It composes all
// internal packages into a working CLI and maps errors to exit codes per the PRD.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ucli "github.com/urfave/cli/v2"
	"golang.org/x/term"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/cli"
	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/keystore"
	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/output"
)

// CLIVersion mirrors the staking-deposit-cli release used to derive the golden
// test fixtures. Bump only after golden-file re-validation passes.
const CLIVersion = "2.7.0"

// version, commit, and date are set at build time via -ldflags.
// Default values are used for local/dev builds.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// errBLSInit is a sentinel used to detect bls.Init() failures in exitCodeFor.
// herumi errors have no exported sentinel, so we wrap them with this.
var errBLSInit = errors.New("bls init failed")

// errMainnetAckRequired is returned by runWithDeps when cfg.Network is mainnet
// but cfg.MainnetAck is false. The CLI gate in app.Action catches this first for
// CLI callers; this sentinel protects non-CLI callers (integration tests, future
// programmatic APIs) and maps to exit code 2.
var errMainnetAckRequired = errors.New("mainnet requires explicit acknowledgement (set Config.MainnetAck = true)")

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
func deriveWithdrawalCredential01(withdrawalAddr string) [32]byte {
	var cred [32]byte
	cred[0] = 0x01
	addr := common.HexToAddress(withdrawalAddr)
	copy(cred[12:], addr[:])
	return cred
}

// pickPassphraseSource returns the appropriate PassphraseSource based on cfg.
// If cfg.PassphraseEnv is non-empty, the source reads from that env var.
// Otherwise it falls back to a TTY prompt written to stderr.
func pickPassphraseSource(cfg cli.Config) keystore.PassphraseSource {
	if cfg.PassphraseEnv != "" {
		return keystore.NewEnvSource(cfg.PassphraseEnv)
	}
	return keystore.NewTermPromptSource(os.Stderr)
}

// pickWriter returns the appropriate output.Writer based on cfg.
// When cfg.DryRun is true, returns a DryRunWriter that writes JSON to w
// (typically os.Stdout); otherwise returns an FSWriter that writes to disk.
func pickWriter(cfg cli.Config, w io.Writer) output.Writer {
	if cfg.DryRun {
		return output.NewDryRunWriter(w)
	}
	return output.NewFSWriter()
}

// deps holds the injectable dependencies for runWithDeps. In production these
// are filled with real implementations; in tests they can be replaced with fakes.
type deps struct {
	// initBLS initialises the herumi BLS library. In tests a no-op can be used.
	initBLS func() error

	// scanner scans a keystore directory and returns a pubkey→path index.
	// It is called once before the per-pubkey loop; no decryption occurs here.
	scanner func(string) (keystore.DirectoryIndex, error)

	// loader is used to load and decrypt the keystore.
	loader keystore.KeyLoader

	// newSigner constructs a BLS signer from a secret.
	newSigner func(secret []byte) (bls.Signer, error)

	// verifier is used for self-verification in the deposit generator.
	verifier bls.Verifier

	// writer is used to persist the deposit data JSON.
	writer output.Writer

	// summaryOut is where the success summary line is written.
	summaryOut io.Writer

	// progressOut is where the per-pubkey progress indicator is written.
	// In production this is os.Stderr; in tests use io.Discard or a bytes.Buffer.
	// If the writer is a *os.File connected to a TTY, a single updating line
	// (using \r) is emitted; otherwise slog.Info events are used (non-TTY / CI).
	progressOut io.Writer

	// logger receives structured debug messages. Set to a discarding logger to
	// suppress all output; set to a text/JSON handler to enable debug logging.
	logger *slog.Logger

	// verifyDepositCLI is called after a successful write when cfg.VerifyWithDepositCLI
	// is true. The production implementation shells out to exec.Command; tests inject
	// a stub that returns a fixed error or nil without spawning any process.
	//
	// Invocation: <cliPath> verify --input-file <outputPath>
	// This matches the staking-deposit-cli >= 2.7.0 verify subcommand.
	verifyDepositCLI func(ctx context.Context, cliPath, outputPath string) error
}

// runDepositCLIVerify is the production implementation of the verifyDepositCLI dep.
// It first probes whether the binary is available via exec.LookPath; if not found
// and the flag was set, it returns ErrDepositCLINotFound (exit code 2). If the
// external process exits non-zero, it returns ErrDepositCLIFailed (exit code 3)
// with the combined stdout+stderr included in the error message.
//
// Invocation: <cliPath> verify --input-file <outputPath>
// This matches staking-deposit-cli >= 2.7.0. See Issue #18 for rationale.
func runDepositCLIVerify(ctx context.Context, cliPath, outputPath string) error {
	if _, err := exec.LookPath(cliPath); err != nil {
		return fmt.Errorf("%w: %q not found in PATH: %v", ErrDepositCLINotFound, cliPath, err)
	}
	cmd := exec.CommandContext(ctx, cliPath, "verify", "--input-file", outputPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrDepositCLIFailed, string(out))
	}
	return nil
}

// buildLogger constructs a *slog.Logger based on the verbose and jsonLogs flags.
// Output is always written to w (os.Stderr in production, a buffer in tests).
// When verbose is true, the handler level is set to Debug; otherwise Info.
// When jsonLogs is true, slog.NewJSONHandler is used; otherwise slog.NewTextHandler.
func buildLogger(verbose, jsonLogs bool, w io.Writer) *slog.Logger {
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
func emitProgress(d deps, cfg cli.Config, done, total int) {
	if cfg.JSONLogs {
		d.logger.Info("signing progress", "done", done, "total", total)
		return
	}
	if isTTY(d.progressOut) {
		_, _ = fmt.Fprintf(d.progressOut, "\rsigning: %d/%d", done, total) // ignore: best-effort progress to stderr; terminal write failure is non-fatal
		if done == total {
			_, _ = fmt.Fprintln(d.progressOut) // ignore: best-effort newline to stderr
		}
		return
	}
	// Non-TTY: emit at each new 10-percentile boundary and always on the last entry.
	pct := done * 100 / total
	prevPct := (done - 1) * 100 / total
	if pct/10 > prevPct/10 || done == total {
		d.logger.Info("signing progress", "done", done, "total", total)
	}
}

// productionDeps returns the deps wired with all real implementations.
// The logger field is intentionally set to a discarding logger here; run()
// overrides it with the cfg-configured logger before calling runWithDeps.
func productionDeps() deps {
	return deps{
		initBLS:          bls.Init,
		scanner:          keystore.ScanDir,
		loader:           keystore.NewLoader(),
		newSigner:        bls.NewSigner,
		verifier:         bls.DefaultVerifier(),
		writer:           output.NewFSWriter(),
		summaryOut:       os.Stderr,
		progressOut:      os.Stderr,
		logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		verifyDepositCLI: runDepositCLIVerify,
	}
}

// runWithDeps is the testable core of run. It accepts a deps struct so tests
// can inject fakes without touching the real BLS or keystore implementations.
// It follows the exact wiring order prescribed by Issue #25.
func runWithDeps(ctx context.Context, cfg cli.Config, d deps) error {
	log := d.logger

	// Step 1: initialise the BLS library (process-global, idempotent).
	log.Debug("bls: initialising library")
	if err := d.initBLS(); err != nil {
		log.Debug("bls: init failed", "error", err)
		return fmt.Errorf("%w: %v", errBLSInit, err)
	}
	log.Debug("bls: library ready")

	// Step 2: resolve network parameters.
	log.Debug("network: looking up params", "network", cfg.Network)
	params, err := network.Lookup(cfg.Network)
	if err != nil {
		return err
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
		return errMainnetAckRequired
	}
	// WithdrawalAddress (EIP-55 validated 0x01 input from --withdrawal-address flag,
	// bound in cli layer per M0.4-1) is received here in the Config load path;
	// derive the 0x01 credential for threading (M0.4-2).
	withdrawalCreds := deriveWithdrawalCredential01(cfg.WithdrawalAddress)
	if cfg.Network == network.Mainnet {
		log.Debug("mainnet: explicit ack verified")
	}

	// Step 3: scan the keystore directory — no decryption yet.
	log.Debug("keystore: scanning directory", "dir", cfg.KeystoreDir)
	index, err := d.scanner(cfg.KeystoreDir)
	if err != nil {
		log.Debug("keystore: scan failed", "error", err)
		return err
	}
	log.Debug("keystore: directory scanned", "count", len(index))

	pwSrc := pickPassphraseSource(cfg)
	defer pwSrc.Zeroize() // M1.1-6: at runWithDeps end (covers all returns post-pw creation)
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

				key, err := d.loader.Load(workerCtx, keystorePath, pwSrc)
				if err != nil {
					log.Debug("keystore: load failed", "pubkey", pkHex, "error", err)
					results <- workerResult{idx: i, err: err}
					workerCancel()
					continue
				}
				log.Debug("keystore: loaded", "pubkey", key.PubkeyHex, "secret_len", len(key.Secret))

				signer, err := d.newSigner(key.Secret)
				key.Zeroize() // zeroize immediately after signer is constructed, even on error path
				if err != nil {
					log.Debug("signer: construction failed", "pubkey", pkHex, "error", err)
					results <- workerResult{idx: i, err: err}
					workerCancel()
					continue
				}
				log.Debug("signer: ready", "pubkey", pkHex)

				gen := deposit.NewGenerator(signer, d.verifier, params)
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
	path, sum, err := d.writer.Write(ctx, cfg.OutputDir, entries, time.Now())
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
		if err := d.verifyDepositCLI(ctx, cfg.DepositCLIPath, path); err != nil {
			log.Debug("verify: deposit CLI check failed", "error", err)
			return err
		}
		log.Debug("verify: deposit CLI cross-check passed")
	}

	// Success: print the summary line.
	printSummary(d.summaryOut, path, sum, len(entries), cfg.Network)
	return nil
}

// run is the urfave/cli action function. It delegates to runWithDeps with
// the production dependency set. The writer and logger are configured here
// from cfg so that productionDeps() remains free of flag knowledge.
func run(ctx context.Context, cfg cli.Config) error {
	d := productionDeps()
	d.writer = pickWriter(cfg, os.Stdout)
	d.logger = buildLogger(cfg.Verbose, cfg.JSONLogs, os.Stderr)
	return runWithDeps(ctx, cfg, d)
}

// printSummary writes the success summary line to w.
// Format: wrote <path> (sha256=<hex>, n=<count>, network=<name>)\n
// When path is empty (DryRunWriter returns ""), the placeholder "<stdout>" is
// used so the summary remains human-readable.
func printSummary(w io.Writer, path, sha256hex string, n int, net network.Network) {
	display := path
	if display == "" {
		display = "<stdout>"
	}
	_, _ = fmt.Fprintf(w, "wrote %s (sha256=%s, n=%d, network=%s)\n", display, sha256hex, n, net) // ignore: best-effort summary write; failure does not affect success path
}

// exitCodeFor maps errors to exit codes per the PRD:
//
//	0 — success (nil)
//	2 — user / configuration errors (bad input, validation)
//	3 — signer / crypto errors (wrong passphrase, BLS failure)
//	4 — user abort (SIGINT/SIGTERM / context.Canceled)
//	1 — fallback for any other error
func exitCodeFor(err error) int {
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
		errors.Is(err, keystore.ErrEnvVarEmpty) ||
		errors.Is(err, keystore.ErrKeystoreNotFound) ||
		errors.Is(err, deposit.ErrPubkeyMismatch) ||
		errors.Is(err, errMainnetAckRequired) ||
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
		errors.Is(err, errBLSInit) ||
		errors.Is(err, ErrDepositCLIFailed) {
		return 3
	}

	// Fallback.
	return 1
}

func main() {
	// Set up a context that cancels on SIGINT/SIGTERM so the pipeline can exit gracefully.
	// Watchdog ensures stop() (unregister) is called on first Done so second signal uses default
	// handler for force-terminate (per arch §9.4, M1.1-2 ACs). On abrupt/force paths (default
	// handler after watchdog, or external kill -9), defers (stop, zeroizes, Closes) may be
	// skipped; Go/C-side secrets (e.g. bls scalars, per ADR-006) rely on OS process exit reclaim.
	// (Full graceful zeroize/env-unset hygiene is in M1.1-5/M1.1-6.)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }()
	defer stop()

	app := cli.NewApp(run)
	app.Version = version
	ucli.VersionPrinter = func(c *ucli.Context) {
		_, _ = fmt.Fprintf(c.App.Writer, "%s version %s (commit=%s, built=%s)\n",
			c.App.Name, c.App.Version, commit, date) // ignore: best-effort version banner to stdout
	}
	if err := app.RunContext(ctx, os.Args); err != nil {
		os.Exit(exitCodeFor(err))
	}
}
