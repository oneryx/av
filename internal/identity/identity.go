// Package identity decides which age identities to use for decryption:
// explicitly given ones, else the default key locations. It is shared by the
// CLI and the av library.
package identity

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/oneryx/av/internal/crypt"
)

// DefaultPaths returns the identity files tried when nothing else is given.
func DefaultPaths() []string {
	var paths []string
	if home, _ := os.UserHomeDir(); home != "" {
		paths = append(paths, filepath.Join(home, ".config", "age", "keys.txt"))
		if runtime.GOOS == "darwin" {
			paths = append(paths, filepath.Join(home, "Library", "Application Support", "age", "keys.txt"))
		}
		paths = append(paths,
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_rsa"),
		)
	}
	return paths
}

// Load returns the identities in files and data if either is given; every
// one of them must load. Otherwise it uses the DefaultPaths, and the ones that
// are missing or invalid are skipped silently.
func Load(files []string, data []byte) ([]crypt.Identity, error) {
	if len(files) == 0 && len(data) == 0 {
		return loadFiles(DefaultPaths(), false)
	}
	var ids []crypt.Identity
	if len(data) > 0 {
		got, err := crypt.ParseIdentityData("identity data", data)
		if err != nil {
			return nil, err
		}
		ids = append(ids, got...)
	}
	got, err := loadFiles(files, true)
	if err != nil {
		return nil, err
	}
	return append(ids, got...), nil
}

func loadFiles(paths []string, strict bool) ([]crypt.Identity, error) {
	var ids []crypt.Identity
	seen := map[string]bool{}
	for _, p := range paths {
		if abs, err := filepath.Abs(p); err == nil {
			if seen[abs] {
				continue
			}
			seen[abs] = true
		}
		got, err := crypt.LoadIdentityFile(p)
		if err != nil {
			if strict {
				return nil, err
			}
			continue
		}
		ids = append(ids, got...)
	}
	return ids, nil
}
