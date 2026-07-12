package keystore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	path := filepath.Join(dir, "keystore.json")
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
	_, err := loader.Load(context.Background(), "/nonexistent/path/keystore.json", newBytesSource(testPassphrase))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrKeystoreMissing")
	}
	if !errors.Is(err, keystore.ErrKeystoreMissing) {
		t.Errorf("Load() error = %v, want errors.Is ErrKeystoreMissing", err)
	}
}

func TestLoad_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
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
	path := filepath.Join(dir, "keystore.json")
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
	os.Unsetenv(varName)

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
	path := filepath.Join(dir, "keystore.json")
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
