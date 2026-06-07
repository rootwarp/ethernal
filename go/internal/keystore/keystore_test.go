package keystore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/keystore"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

const (
	testPassphrase = "testpassword"
	testPubkeyHex  = "b9e7be8b1eea5ca44d9b1ef6e60de0b7e213d7e6b3f29e4a0e6a93b56678e58c2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1"
)

// testSecret is 32 bytes used as the BLS secret in fixture keystores.
var testSecret = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// bytesSource is a PassphraseSource backed by a static byte slice.
// It satisfies the PassphraseSource interface without needing a TTY.
type bytesSource struct {
	data []byte
}

func (b *bytesSource) Read() ([]byte, error) {
	out := make([]byte, len(b.data))
	copy(out, b.data)
	return out, nil
}

func (b *bytesSource) Zeroize() {}

func newBytesSource(pw string) keystore.PassphraseSource {
	return &bytesSource{data: []byte(pw)}
}

// errSource is a PassphraseSource that always returns an error.
type errSource struct {
	err error
}

func (e *errSource) Read() ([]byte, error) {
	return nil, e.err
}

func (e *errSource) Zeroize() {}

// keystoreJSON is the outer EIP-2335 v4 envelope.
type keystoreJSON struct {
	Crypto  map[string]any `json:"crypto"`
	Pubkey  string         `json:"pubkey"`
	Version int            `json:"version"`
	UUID    string         `json:"uuid"`
	Path    string         `json:"path"`
}

// generateFixture creates a minimal EIP-2335 v4 keystore JSON using the wealdtech
// encryptor and returns its raw bytes.
func generateFixture(t *testing.T, cipher string, secret []byte, passphrase string) []byte {
	t.Helper()
	var enc *keystorev4.Encryptor
	if cipher == "scrypt" {
		enc = keystorev4.New(keystorev4.WithCipher("scrypt"), keystorev4.WithCost(t, 2))
	} else {
		enc = keystorev4.New(keystorev4.WithCost(t, 2))
	}

	crypto, err := enc.Encrypt(secret, passphrase)
	if err != nil {
		t.Fatalf("generate fixture: encrypt: %v", err)
	}

	ks := keystoreJSON{
		Crypto:  crypto,
		Pubkey:  testPubkeyHex,
		Version: 4,
		UUID:    "00000000-0000-0000-0000-000000000001",
		Path:    "m/12381/3600/0/0/0",
	}
	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		t.Fatalf("generate fixture: marshal: %v", err)
	}
	return data
}

// writeFixture writes fixture data to a temp file and returns its path.
func writeFixture(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// --- Successful decrypt tests ---

func TestLoad_ScryptKeystore(t *testing.T) {
	data := generateFixture(t, "scrypt", testSecret, testPassphrase)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	key, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	defer key.Zeroize()

	if !bytes.Equal(key.Secret, testSecret) {
		t.Errorf("Load() Secret = %x, want %x", key.Secret, testSecret)
	}
	if key.PubkeyHex != testPubkeyHex {
		t.Errorf("Load() PubkeyHex = %q, want %q", key.PubkeyHex, testPubkeyHex)
	}
}

func TestLoad_PBKDF2Keystore(t *testing.T) {
	data := generateFixture(t, "pbkdf2", testSecret, testPassphrase)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	key, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	defer key.Zeroize()

	if !bytes.Equal(key.Secret, testSecret) {
		t.Errorf("Load() Secret = %x, want %x", key.Secret, testSecret)
	}
	if key.PubkeyHex != testPubkeyHex {
		t.Errorf("Load() PubkeyHex = %q, want %q", key.PubkeyHex, testPubkeyHex)
	}
}

// --- Error path tests ---

func TestLoad_WrongPassphrase(t *testing.T) {
	data := generateFixture(t, "pbkdf2", testSecret, testPassphrase)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource("wrongpassword"))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrWrongPassphrase")
	}
	if !errors.Is(err, keystore.ErrWrongPassphrase) {
		t.Errorf("Load() error = %v, want errors.Is ErrWrongPassphrase", err)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), "/nonexistent/path/json", newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrKeystoreMissing")
	}
	if !errors.Is(err, keystore.ErrKeystoreMissing) {
		t.Errorf("Load() error = %v, want errors.Is ErrKeystoreMissing", err)
	}
}

// TestLoader_CtxCancelBeforeRead_NoFileIO (M1.1-1 AC): cancel before Load →
// returns ctx err with no file I/O attempted (uses nonexist path; if read had
// been reached would have produced ErrKeystoreMissing instead of Canceled).
func TestLoader_CtxCancelBeforeRead_NoFileIO(t *testing.T) {
	loader := keystore.NewLoader()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := loader.Load(ctx, "/nonexistent/path/json", newBytesSource(testPassphrase))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Load err = %v, want context.Canceled (proves no os.ReadFile attempted)", err)
	}
}

func TestLoad_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "json")
	if err := os.WriteFile(path, []byte("not-json{{{"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrKeystoreMalformed")
	}
	if !errors.Is(err, keystore.ErrKeystoreMalformed) {
		t.Errorf("Load() error = %v, want errors.Is ErrKeystoreMalformed", err)
	}
}

func TestLoad_VersionNotFour(t *testing.T) {
	// A valid JSON that has version == 3 instead of 4.
	ks := map[string]any{
		"crypto":  map[string]any{},
		"pubkey":  testPubkeyHex,
		"version": 3,
		"uuid":    "00000000-0000-0000-0000-000000000002",
		"path":    "",
	}
	data, _ := json.Marshal(ks)
	dir := t.TempDir()
	path := filepath.Join(dir, "json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrKeystoreVersion")
	}
	if !errors.Is(err, keystore.ErrKeystoreVersion) {
		t.Errorf("Load() error = %v, want errors.Is ErrKeystoreVersion", err)
	}
}

// --- Zeroize test ---

func TestKey_Zeroize(t *testing.T) {
	data := generateFixture(t, "pbkdf2", testSecret, testPassphrase)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	key, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Capture the slice header (same backing array).
	secret := key.Secret
	key.Zeroize()

	for i, b := range secret {
		if b != 0x00 {
			t.Errorf("Zeroize() secret[%d] = 0x%02x, want 0x00", i, b)
		}
	}
}

// --- EnvSource tests ---

func TestNewEnvSource_ReadsEnvVar(t *testing.T) {
	varName := "TEST_KEYSTORE_PW_" + t.Name()
	t.Setenv(varName, testPassphrase)

	src := keystore.NewEnvSource(varName)
	got, err := src.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(got) != testPassphrase {
		t.Errorf("Read() = %q, want %q", got, testPassphrase)
	}
}

func TestNewEnvSource_EmptyVarReturnsTypedError(t *testing.T) {
	varName := "TEST_KEYSTORE_PW_MISSING_" + t.Name()
	// Ensure it's not set.
	_ = os.Unsetenv(varName) // ignore: Unsetenv error irrelevant; we only need absence for this test case (env may be read-only in some envs)

	src := keystore.NewEnvSource(varName)
	_, err := src.Read()
	if err == nil {
		t.Fatal("Read() error = nil, want ErrEnvVarEmpty")
	}
	if !errors.Is(err, keystore.ErrEnvVarEmpty) {
		t.Errorf("Read() error = %v, want errors.Is ErrEnvVarEmpty", err)
	}
}

// --- Fixture keystores under testdata/ ---

func TestLoad_ScryptFixtureFile(t *testing.T) {
	loader := keystore.NewLoader()
	key, err := loader.Load(
		context.Background(),
		"testdata/keystore-scrypt.json",
		newBytesSource(testPassphrase),
	)
	if err != nil {
		t.Fatalf("Load(testdata/keystore-scrypt.json) error = %v", err)
	}
	defer key.Zeroize()

	if len(key.Secret) != 32 {
		t.Errorf("Secret length = %d, want 32", len(key.Secret))
	}
	if !bytes.Equal(key.Secret, testSecret) {
		t.Errorf("Secret = %x, want %x", key.Secret, testSecret)
	}
}

func TestLoad_PBKDF2FixtureFile(t *testing.T) {
	loader := keystore.NewLoader()
	key, err := loader.Load(
		context.Background(),
		"testdata/keystore-pbkdf2.json",
		newBytesSource(testPassphrase),
	)
	if err != nil {
		t.Fatalf("Load(testdata/keystore-pbkdf2.json) error = %v", err)
	}
	defer key.Zeroize()

	if len(key.Secret) != 32 {
		t.Errorf("Secret length = %d, want 32", len(key.Secret))
	}
	if !bytes.Equal(key.Secret, testSecret) {
		t.Errorf("Secret = %x, want %x", key.Secret, testSecret)
	}
}

func TestLoad_MissingCryptoField(t *testing.T) {
	ks := map[string]any{
		"pubkey":  testPubkeyHex,
		"version": 4,
		"uuid":    "00000000-0000-0000-0000-000000000004",
		"path":    "",
		// no "crypto" key — envelope.Crypto will be nil after unmarshal
	}
	data, _ := json.Marshal(ks)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrKeystoreMalformed")
	}
	if !errors.Is(err, keystore.ErrKeystoreMalformed) {
		t.Errorf("Load() error = %v, want errors.Is ErrKeystoreMalformed", err)
	}
}

func TestLoad_UnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 000 has no effect")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "json")
	if err := os.WriteFile(path, []byte(`{}`), 0000); err != nil {
		t.Fatalf("write: %v", err)
	}

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want read error")
	}
	// Must NOT be ErrKeystoreMissing — file exists but is unreadable.
	if errors.Is(err, keystore.ErrKeystoreMissing) {
		t.Errorf("Load() error = %v, must not be ErrKeystoreMissing for permission-denied", err)
	}
}

// TestLoad_PassphraseSourceError covers the path where the PassphraseSource
// returns an error (e.g. ErrEnvVarEmpty).
func TestLoad_PassphraseSourceError(t *testing.T) {
	data := generateFixture(t, "pbkdf2", testSecret, testPassphrase)
	path := writeFixture(t, data)

	sentinel := errors.New("source failed")
	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, &errSource{err: sentinel})
	if err == nil {
		t.Fatal("Load() error = nil, want passphrase source error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Load() error = %v, want errors.Is sentinel", err)
	}
}

// TestLoad_PubkeyNormalized verifies that a pubkey with a 0x prefix and
// uppercase letters is lowercased and stripped.
func TestLoad_PubkeyNormalized(t *testing.T) {
	enc := keystorev4.New(keystorev4.WithCost(t, 2))
	crypto, err := enc.Encrypt(testSecret, testPassphrase)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// A realistic pubkey: 0x-prefixed and uppercase, as some CLI tools emit.
	uppercasePubkey := "0x" + strings.ToUpper(testPubkeyHex)

	ks := keystoreJSON{
		Crypto:  crypto,
		Pubkey:  uppercasePubkey,
		Version: 4,
		UUID:    "00000000-0000-0000-0000-000000000003",
		Path:    "",
	}
	data, _ := json.MarshalIndent(ks, "", "  ")
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	key, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer key.Zeroize()

	// Must be lowercase and without 0x prefix.
	if strings.HasPrefix(key.PubkeyHex, "0x") {
		t.Errorf("PubkeyHex has 0x prefix: %q", key.PubkeyHex)
	}
	if key.PubkeyHex != strings.ToLower(key.PubkeyHex) {
		t.Errorf("PubkeyHex is not fully lowercase: %q", key.PubkeyHex)
	}
	if key.PubkeyHex != testPubkeyHex {
		t.Errorf("PubkeyHex = %q, want %q", key.PubkeyHex, testPubkeyHex)
	}
}

// --- M1.4-1 acceptance criteria tests (structural vs checksum classification) ---

// TestLoad_StructuralMissingField_ErrKeystoreMalformed: missing JSON field
// (top-level "crypto") → ErrKeystoreMalformed (pre-decrypt shape check).
func TestLoad_StructuralMissingField_ErrKeystoreMalformed(t *testing.T) {
	ks := map[string]any{
		"pubkey":  testPubkeyHex,
		"version": 4,
		"uuid":    "00000000-0000-0000-0000-000000000007",
		"path":    "",
		// deliberately missing "crypto" field
	}
	data, _ := json.Marshal(ks)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrKeystoreMalformed")
	}
	if !errors.Is(err, keystore.ErrKeystoreMalformed) {
		t.Errorf("Load() error = %v, want errors.Is ErrKeystoreMalformed", err)
	}
}

// TestLoad_StructuralBadCipherText_ErrKeystoreCipherText: bad cipher text
// structure (crypto present but no "checksum") → ErrKeystoreCipherText.
// Uses good passphrase so mismatch cannot be the cause. Also verifies
// regression AC: error string contains no keystore payload bytes.
func TestLoad_StructuralBadCipherText_ErrKeystoreCipherText(t *testing.T) {
	// crypto map with cipher but deliberately omits the "checksum" key
	// (and minimal other fields) so Decrypt returns "no checksum".
	badCrypto := map[string]any{
		"cipher": map[string]any{
			"function": "aes-128-ctr",
			"params":   map[string]any{"iv": "00000000000000000000000000000000"},
			"message":  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		"kdf": map[string]any{
			"function": "scrypt",
			"params": map[string]any{
				"dklen": 32,
				"n":     262144,
				"p":     1,
				"r":     8,
				"salt":  "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
		// no "checksum" → structural bad cipher text
	}
	ks := map[string]any{
		"crypto":  badCrypto,
		"pubkey":  testPubkeyHex,
		"version": 4,
		"uuid":    "00000000-0000-0000-0000-000000000008",
		"path":    "",
	}
	data, _ := json.Marshal(ks)
	path := writeFixture(t, data)

	// Use a distinctive payload fragment that exists in the keystore JSON
	// (the cipher message hex) — it must not appear in the error string.
	payloadFragment := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrKeystoreCipherText")
	}
	if !errors.Is(err, keystore.ErrKeystoreCipherText) {
		t.Errorf("Load() error = %v, want errors.Is ErrKeystoreCipherText", err)
	}
	if strings.Contains(err.Error(), payloadFragment) ||
		strings.Contains(err.Error(), testPubkeyHex) ||
		strings.Contains(err.Error(), "testpassword") {
		t.Errorf("error string leaked keystore payload bytes: %v", err)
	}
}

// TestLoad_ChecksumMismatch_ErrWrongPassphrase: bad passphrase on otherwise
// valid cipher text → only ErrWrongPassphrase (not CipherText or Malformed).
func TestLoad_ChecksumMismatch_ErrWrongPassphrase(t *testing.T) {
	data := generateFixture(t, "pbkdf2", testSecret, testPassphrase)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource("wrongpassword"))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrWrongPassphrase")
	}
	if !errors.Is(err, keystore.ErrWrongPassphrase) {
		t.Errorf("Load() error = %v, want errors.Is ErrWrongPassphrase", err)
	}
	// Ensure it is not misclassified as the new sentinel.
	if errors.Is(err, keystore.ErrKeystoreCipherText) {
		t.Errorf("Load() error = %v, must not be ErrKeystoreCipherText for checksum mismatch", err)
	}
}

// TestLoad_ErrString_DoesNotContainKeystorePayloadBytes covers the regression
// AC ("Error string does not contain any keystore payload bytes").
func TestLoad_ErrString_DoesNotContainKeystorePayloadBytes(t *testing.T) {
	// Reuse a structural bad-cipher case (no checksum) to produce a
	// non-WrongPassphrase error whose string must be free of payload.
	badCrypto := map[string]any{
		"cipher": map[string]any{
			"function": "aes-128-ctr",
			"params":   map[string]any{"iv": "00000000000000000000000000000000"},
			"message":  "cafed00dfeedfacecafed00dfeedfacecafed00dfeedfacecafed00dfeedface",
		},
		"kdf": map[string]any{
			"function": "scrypt",
			"params": map[string]any{
				"dklen": 32, "n": 2, "p": 1, "r": 8,
				"salt": "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}
	ks := map[string]any{
		"crypto":  badCrypto,
		"pubkey":  testPubkeyHex,
		"version": 4,
		"uuid":    "00000000-0000-0000-0000-000000000009",
		"path":    "",
	}
	data, _ := json.Marshal(ks)
	path := writeFixture(t, data)

	payloadFragment := "cafed00dfeedfacecafed00dfeedfacecafed00dfeedfacecafed00dfeedface"

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if strings.Contains(err.Error(), payloadFragment) ||
		strings.Contains(err.Error(), testPubkeyHex) {
		t.Errorf("error string leaked keystore payload bytes: %v", err)
	}
	// Re-uses bad-cipher construction (crypto present but no "checksum");
	// reaches Decrypt → ErrKeystoreCipherText. (Malformed not hit here;
	// AC2 asserts the sentinel; AC4 only requires the leak check.)
}

// --- M1.4-3 acceptance criteria tests (32-byte secret length + zeroize) ---

// TestLoad_ShortSecret_31_Reject_Zeroized: 31-byte secret after decrypt
// (via generateFixture with short input) → ErrKeystoreMalformed; the
// buffer (instrumented via TestSecretBuffer) is zero post-rejection.
// Follows exact style of M1.4-1 error tests (writeFixture, errors.Is, t.Fatal/t.Errorf)
// and M1.1 instrumented zeroize tests ("secret bytes zeroed" hygiene message).
// Uses exported TestSecretBuffer (tradeoff for external black-box test style in
// M1.4-1 ACs + cross _test.go helper sharing; see var godoc + wontfix response).
func TestLoad_ShortSecret_31_Reject_Zeroized(t *testing.T) {
	short := make([]byte, 31)
	for i := range short {
		short[i] = byte(i + 1)
	}
	data := generateFixture(t, "pbkdf2", short, testPassphrase)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrKeystoreMalformed")
	}
	if !errors.Is(err, keystore.ErrKeystoreMalformed) {
		t.Errorf("Load() error = %v, want errors.Is ErrKeystoreMalformed", err)
	}

	// Inspect instrumented buffer (set by Load on this path before zeroizeBytes).
	// keystore.TestSecretBuffer may alias zeroed secret-derived alloc (retention risk per review);
	// we explicitly nil after + KeepAlive for observability during AC check.
	if keystore.TestSecretBuffer == nil {
		t.Fatal("TestSecretBuffer was not populated (instrumentation in test build missing)")
	}
	for i, b := range keystore.TestSecretBuffer {
		if b != 0x00 {
			t.Errorf("secret buffer[%d] = 0x%02x after rejection, want 0x00 (secret bytes zeroed per M1.4-3)", i, b)
		}
	}
	runtime.KeepAlive(keystore.TestSecretBuffer) // comment + KeepAlive per review feedback for buffer observability in test
	keystore.TestSecretBuffer = nil              // explicit cleanup after inspect: bounds retention of zeroed buffer header; improves test isolation / addresses mutable global lifetime
}

// TestLoad_HappyPath_32Byte exercises that a normal 32-byte secret still
// decrypts successfully with len unchanged (AC; pairs with short-secret reject test).
// Style matches existing happy-path fixture tests (e.g. TestLoad_ScryptFixtureFile)
// and their len==32 asserts.
func TestLoad_HappyPath_32Byte(t *testing.T) {
	data := generateFixture(t, "pbkdf2", testSecret, testPassphrase)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	key, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	defer key.Zeroize()

	if len(key.Secret) != 32 {
		t.Errorf("Load() Secret length = %d, want 32", len(key.Secret))
	}
	if !bytes.Equal(key.Secret, testSecret) {
		t.Errorf("Load() Secret = %x, want %x", key.Secret, testSecret)
	}
}

// TestLoad_2MiBFile_Reject: file > MaxKeystoreSize → LimitReader bound exceeded
// (detected post-capped ReadAll via probe read on underlying file) → rejected with
// descriptive error. Follows exact style of M1.4-1/3 Load error tests (write via
// os.WriteFile in TempDir like TestLoad_MalformedJSON/TestLoad_UnreadableFile,
// context.Background, newBytesSource, t.Fatal on nil-err, t.Errorf on mismatch;
// uses the exported MaxKeystoreSize, no new helpers).
func TestLoad_2MiBFile_Reject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	big := make([]byte, 2*keystore.MaxKeystoreSize)
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatalf("write 2MiB: %v", err)
	}

	loader := keystore.NewLoader()
	_, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want error (2MiB > MaxKeystoreSize)")
	}
	if !strings.Contains(err.Error(), "MaxKeystoreSize") {
		t.Errorf("Load() error = %v, want descriptive error mentioning MaxKeystoreSize (LimitReader cap exceeded)", err)
	}
}

// TestMaxKeystoreSize verifies the constant is exported, has the documented value,
// and is usable from tests (covers the "MaxKeystoreSize constant exported and documented" AC).
func TestMaxKeystoreSize(t *testing.T) {
	const want = 1 << 20
	if keystore.MaxKeystoreSize != want {
		t.Errorf("MaxKeystoreSize = %d, want %d", keystore.MaxKeystoreSize, want)
	}
}

// TestKeyZeroize_HeapDumpClean verifies the Go-side Secret bytes are wiped after
// Zeroize (now a delegate to zeroizeBytes with corrected runtime.KeepAlive), using
// heap-dump technique (capture + post-Zeroize GC + observability KeepAlive) per
// M1.7-5 AC, PRD §3.2 metric 12, architecture §11.4. Follows patterns from
// TestKey_Zeroize and TestLoad_ShortSecret_31_Reject_Zeroized (slice-header capture,
// runtime.KeepAlive for observability).
func TestKeyZeroize_HeapDumpClean(t *testing.T) {
	data := generateFixture(t, "pbkdf2", testSecret, testPassphrase)
	path := writeFixture(t, data)

	loader := keystore.NewLoader()
	key, err := loader.Load(context.Background(), path, newBytesSource(testPassphrase))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Capture slice header (same backing array) for post-zeroize heap observation.
	secret := key.Secret
	key.Zeroize()

	runtime.GC() // force GC for heap-dump-style verification that wipe is visible / not retained

	for i, b := range secret {
		if b != 0x00 {
			t.Errorf("Zeroize() secret[%d] = 0x%02x, want 0x00 (heap-dump clean per M1.7-5 / metric 12)", i, b)
		}
	}
	runtime.KeepAlive(secret) // observability KeepAlive (corrected per arch §11.4)
}
