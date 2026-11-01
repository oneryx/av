// Package av reads files encrypted with age by the av command, so
// applications can use them without shelling out to av.
//
//	vars, err := av.Read("")              // decrypt ./.env.age into a map
//	err := av.Load("config/prod.env.age") // or set them as environment variables
//	text, err := av.Decrypt("secrets.age") // any other .age file, as raw bytes
//
// Identities are those given with WithIdentityFiles or WithIdentityData. If
// neither is given, av uses the default key locations (~/.config/age/keys.txt,
// ~/Library/Application Support/age/keys.txt on macOS, ~/.ssh/id_ed25519,
// ~/.ssh/id_rsa).
//
// The package never prompts.
package av

import (
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/oneryx/av/internal/crypt"
	"github.com/oneryx/av/internal/dotenv"
	"github.com/oneryx/av/internal/identity"
)

// DefaultPath is the file read when Read or Load is given an empty path.
const DefaultPath = ".env.age"

// ErrNoIdentity is returned (wrapped) when no identity could be found to
// decrypt a file that is encrypted to recipients.
var ErrNoIdentity = crypt.ErrNoIdentity

// An Option configures Read, Load and Decrypt.
type Option func(*config)

type config struct {
	files []string
	data  []byte
}

// WithIdentityFiles uses these identity files (age keys or SSH private keys)
// instead of the default locations. A missing or invalid file is an error.
func WithIdentityFiles(paths ...string) Option {
	return func(c *config) { c.files = append(c.files, paths...) }
}

// WithIdentityData uses identities given as content, e.g. a key fetched from
// a secret manager, instead of the default locations. It can be combined with
// WithIdentityFiles.
func WithIdentityData(data []byte) Option {
	return func(c *config) { c.data = append(c.data, data...) }
}

// Decrypt decrypts the .age file at path and returns its plaintext as is,
// whatever it holds. If the file doesn't exist, the error matches
// fs.ErrNotExist.
func Decrypt(path string, opts ...Option) ([]byte, error) {
	var c config
	for _, opt := range opts {
		opt(&c)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("av: %w", err)
	}
	loadIDs := func() ([]age.Identity, error) {
		ids, err := identity.Load(c.files, c.data)
		return crypt.AgeIdentities(ids), err
	}
	plain, err := crypt.Decrypt(data, loadIDs)
	if err != nil {
		return nil, fmt.Errorf("av: %s: %w", path, err)
	}
	return plain, nil
}

// Read decrypts and parses the encrypted .env file at path (DefaultPath if
// path is ""). Only *.env.age files are accepted; use Decrypt for others. If
// the file doesn't exist, the error matches fs.ErrNotExist. Files with
// invalid lines or duplicate keys are rejected.
func Read(path string, opts ...Option) (map[string]string, error) {
	if path == "" {
		path = DefaultPath
	}
	if !strings.HasSuffix(path, ".env.age") {
		return nil, fmt.Errorf("av: %s is not a .env.age file (use Decrypt for other files)", path)
	}
	plain, err := Decrypt(path, opts...)
	if err != nil {
		return nil, err
	}

	entries, errs := dotenv.Parse(string(plain))
	if len(errs) > 0 {
		// Only line numbers and reasons: the line text may hold secrets, and
		// errors from a library tend to end up in logs.
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = fmt.Sprintf("line %d: %s", e.Line, e.Msg)
		}
		return nil, fmt.Errorf("av: %s contains invalid lines (fix with `av edit`):\n%s", path, strings.Join(msgs, "\n"))
	}
	vars := make(map[string]string, len(entries))
	for _, e := range entries {
		vars[e.Key] = e.Value
	}
	return vars, nil
}

// Load calls Read and sets each variable in the process environment, unless
// it is already set: the real environment wins over the file.
func Load(path string, opts ...Option) error {
	vars, err := Read(path, opts...)
	if err != nil {
		return err
	}
	for k, v := range vars {
		if _, ok := os.LookupEnv(k); ok {
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			return fmt.Errorf("av: %w", err)
		}
	}
	return nil
}
