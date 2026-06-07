// Package keystore loads and decrypts EIP-2335 v4 keystore files.
// It exposes typed sentinel errors and a zeroize hook for key material.
package keystore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

// Sentinel errors. Callers use errors.Is to distinguish them.
var (
	// ErrKeystoreMissing is returned when the keystore file does not exist.
	ErrKeystoreMissing = errors.New("keystore file not found")

	// ErrKeystoreMalformed is returned when the keystore file cannot be parsed
	// as valid EIP-2335 JSON, or the decrypted secret is not exactly 32 bytes
	// (see Load for full error mapping and the post-decrypt length invariant).
	ErrKeystoreMalformed = errors.New("keystore JSON malformed")

	// ErrKeystoreCipherText is returned for structural problems inside the
	// "crypto" object (e.g. missing "checksum" or "cipher", unsupported KDF,
	// invalid IV, bad hex). Only the checksum mismatch on a well-formed
	// ciphertext maps to ErrWrongPassphrase.
	ErrKeystoreCipherText = errors.New("keystore cipher text invalid")

	// ErrKeystoreVersion is returned when the version field is not 4.
	ErrKeystoreVersion = errors.New("keystore version must be 4")

	// ErrWrongPassphrase is returned when decryption fails due to an incorrect
	// passphrase (checksum mismatch from the wealdtech encryptor).
	ErrWrongPassphrase = errors.New("wrong passphrase")

	// ErrEnvVarEmpty is returned by NewEnvSource when the named environment
	// variable is unset or empty. This maps to exit code 2 (user error).
	ErrEnvVarEmpty = errors.New("passphrase environment variable is unset or empty")
)

// MaxKeystoreSize is the maximum number of bytes that will be read from a
// keystore file by ScanDir (for pubkey indexing) or Load (for full decrypt).
// Files larger than this are rejected by Load with a descriptive error.
// Both paths use io.LimitReader to enforce the bound. Value is 1 MiB per
// architecture §15 / FR-P1-E4 (GO-030).
const MaxKeystoreSize = 1 << 20

// wealdtechInvalidChecksum is the exact string returned *only* by
// wealdtech/go-eth2-wallet-encryptor-keystorev4@v1.4.1/decrypt.go:168
// (in confirmChecksum, after successful KDF+key derive) for the
// wrong-passphrase case. All other Decrypt errors are structural and
// must map to ErrKeystoreCipherText (see arch §6.4/§8.2/§15, M1.4-1).
// Centralized here (not substring) to reduce brittleness on lib bump;
// the literal is never exposed to callers (fixed sentinels + path only).
const wealdtechInvalidChecksum = "invalid checksum"

// TestSecretBuffer is set by the short-secret rejection path inside Load so that
// the instrumented acceptance test TestLoad_ShortSecret_31_Reject_Zeroized
// (M1.4-3) can obtain a reference to the buffer and assert it is zeroed
// post-rejection. Exported (capitalized) test hook only because all keystore
// AC tests (incl. M1.4-1 structural) use the external "keystore_test" package
// + `keystore.` prefix + black-box style (exact per summary; shared lowercase
// test helpers like testSecret across *_test.go files like gen_fixtures_test.go
// would require non-scoped edits or new file to unexport). Prod code never
// reads it. May retain slice header to (zeroed) buffer until AC test nils it
// after inspect; concurrent short Loads may race the write (wontfixed: matches
// M1.1-5 testSignDecodeBuffer precedent exactly; necessary for "instrument test
// build to inspect the buffer" AC under no-new-files constraint).
var TestSecretBuffer []byte

// Key holds the decrypted key material returned by a KeyLoader.
// Callers must call Zeroize after use; the garbage collector does not
// clear key material.
type Key struct {
	// Secret is the raw 32-byte BLS signing secret. Zeroize after use.
	Secret []byte

	// PubkeyHex is the lowercase hex-encoded public key declared in the keystore
	// JSON, without a 0x prefix. It is passed through as-is from the JSON; the
	// loader does not validate its length or that it matches Secret.
	PubkeyHex string
}

// Zeroize overwrites every byte of Secret with 0x00.
// This must be called explicitly; Go's GC does not zero memory.
func (k *Key) Zeroize() {
	for i := range k.Secret {
		k.Secret[i] = 0x00
	}
}

// PassphraseSource abstracts where the passphrase comes from so the loader
// can be tested without a TTY or a live environment variable.
type PassphraseSource interface {
	// Read returns the passphrase bytes. The loader will zeroize the slice
	// immediately after decryption. Implementations must not retain the
	// returned slice.
	Read() ([]byte, error)
	// Zeroize is called at end of run (M1.1-6) for secret hygiene on pw
	// sources (env/term); impls are no-op or best-effort (Go-side only).
	Zeroize()
}

// KeyLoader loads and decrypts an EIP-2335 v4 keystore file.
type KeyLoader interface {
	// Load reads and decrypts the keystore at path using the passphrase
	// obtained from pw. The returned Key.Secret must be zeroized by the
	// caller via Key.Zeroize.
	Load(ctx context.Context, path string, pw PassphraseSource) (Key, error)
}

// keystoreEnvelope is the top-level structure of an EIP-2335 v4 keystore JSON.
type keystoreEnvelope struct {
	Crypto  map[string]any `json:"crypto"`
	Pubkey  string         `json:"pubkey"`
	Version int            `json:"version"`
	UUID    string         `json:"uuid"`
	Path    string         `json:"path"`
}

// loader is the concrete implementation of KeyLoader.
type loader struct{}

// NewLoader returns a KeyLoader that reads EIP-2335 v4 keystore files.
func NewLoader() KeyLoader {
	return &loader{}
}

// Load reads and decrypts the keystore at path.
//
// It honours ctx: checks ctx.Err() before file read, before pw.Read(), and
// before Decrypt (per M1.1-1 / arch §9.2). Decrypt (scrypt via wealdtech)
// cannot be cancelled mid-flight — only at these boundaries.
//
// Success: the returned Key always has len(Secret) == 32 (the 32-byte
// invariant per architecture §6.4 / FR-P1-E3).
//
// Error mapping:
//   - file not found            → ErrKeystoreMissing
//   - invalid JSON / schema     → ErrKeystoreMalformed
//   - version field != 4        → ErrKeystoreVersion
//   - bad cipher text structure → ErrKeystoreCipherText
//   - checksum mismatch on well-formed ciphertext → ErrWrongPassphrase
//     (all other Decrypt structural failures → ErrKeystoreCipherText)
//   - decrypted secret len != 32 → ErrKeystoreMalformed (partial secret
//     buffer zeroized via zeroizeBytes before return)
func (l *loader) Load(ctx context.Context, path string, pw PassphraseSource) (Key, error) {
	if err := ctx.Err(); err != nil {
		return Key{}, err
	}
	// Wrap read with io.LimitReader + MaxKeystoreSize per M1.4-4 / arch §6.4/§15.
	// Probe after the capped read to detect bound exceeded (for >Max files,
	// ReadAll on Limit succeeds with prefix; the extra byte from underlying f
	// indicates the file was larger).
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Key{}, fmt.Errorf("%w: %s", ErrKeystoreMissing, path)
		}
		return Key{}, fmt.Errorf("read keystore %s: %w", path, err)
	}
	defer func() { _ = f.Close() }() // ignore: best-effort on read-only keystore fd after LimitReader cap + probe (matches explicit ignore discipline for closes in package per CONVENTIONS)
	limited := io.LimitReader(f, MaxKeystoreSize)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return Key{}, fmt.Errorf("read keystore %s: %w", path, err)
	}
	// Detect > MaxKeystoreSize (LimitReader bound exceeded case).
	var probe [1]byte
	if n, _ := f.Read(probe[:]); n > 0 {
		return Key{}, fmt.Errorf("read keystore %s: size exceeds MaxKeystoreSize (%d bytes)", path, MaxKeystoreSize)
	}
	// ignore probeErr from Read (via _): only n>0 matters to detect data beyond MaxKeystoreSize (EOF/other err means no extra bytes); explicit per CONVENTIONS for justified discards; smallest change preserving prior behavior and ACs (static 2MiB case + capped prefix processing)

	var envelope keystoreEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Key{}, fmt.Errorf("%w: %s: %v", ErrKeystoreMalformed, path, err)
	}

	// Version check first — gives the most diagnostic error for malformed v3 keystores.
	if envelope.Version != 4 {
		return Key{}, fmt.Errorf("%w: %s: got %d", ErrKeystoreVersion, path, envelope.Version)
	}

	// Validate the crypto field is present after confirming version.
	if envelope.Crypto == nil {
		return Key{}, fmt.Errorf("%w: %s: missing crypto field", ErrKeystoreMalformed, path)
	}

	if err := ctx.Err(); err != nil {
		return Key{}, err
	}
	// Source the passphrase.
	passBytes, err := pw.Read()
	if err != nil {
		return Key{}, fmt.Errorf("passphrase source: %w", err)
	}

	if err := ctx.Err(); err != nil {
		zeroizeBytes(passBytes)
		return Key{}, err
	}

	// Decrypt. The wealdtech API takes a string. We convert from []byte and
	// defer zeroization of the original slice so it is always cleared,
	// including on the decrypt-failure path. The string copy itself cannot be
	// zeroed (Go strings are immutable); it will persist until GC — this is
	// unavoidable with the current wealdtech API signature.
	passString := string(passBytes)
	defer zeroizeBytes(passBytes)

	if err := ctx.Err(); err != nil {
		return Key{}, err
	}
	enc := keystorev4.New()
	secret, err := enc.Decrypt(envelope.Crypto, passString)
	if err != nil {
		// Per architecture §6.4 / §8.2 / §15 and M1.4-1: only the exact
		// wealdtechInvalidChecksum from a well-formed ciphertext means wrong
		// passphrase (exit 3). All other Decrypt failures (structural
		// problems with the cipher text) map to the fixed sentinel
		// ErrKeystoreCipherText (exit 2). We never %w the decoder error
		// itself (it or its wrappers might embed secret material in some
		// implementations). %w used for the (safe, non-secret) inner on
		// WrongPassphrase per arch rule 2 for non-secret errors.
		if err.Error() == wealdtechInvalidChecksum {
			return Key{}, fmt.Errorf("%w: %w", ErrWrongPassphrase, err)
		}
		return Key{}, fmt.Errorf("%w: %s", ErrKeystoreCipherText, path)
	}
	if len(secret) != 32 {
		// Per architecture §6.4 / FR-P1-E3 (GO-029) / M1.4-3: enforce 32-byte
		// secret after decrypt. Zeroize the partial via the same helper used
		// for passphrases (M0.8/M1.1 patterns) and return Malformed (exit 2).
		// Note: 0-byte/empty or >32 also hit this (consistent); AC uses 31B.
		TestSecretBuffer = secret // capture header (no clone) so AC test observes *exact* Decrypt-returned buffer post-zeroizeBytes; error path only (secret never returned to caller); test nils after inspect to bound retention
		zeroizeBytes(secret)
		return Key{}, fmt.Errorf("%w: %s", ErrKeystoreMalformed, path)
	}

	pubkeyHex := strings.ToLower(strings.TrimPrefix(envelope.Pubkey, "0x"))

	return Key{
		Secret:    secret,
		PubkeyHex: pubkeyHex,
	}, nil
}

// zeroizeBytes overwrites every byte of b with 0x00.
// runtime.KeepAlive prevents the compiler from treating the writes as dead stores.
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0x00
	}
	runtime.KeepAlive(b)
}
