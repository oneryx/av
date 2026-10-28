// Package identity decides which age identities to use for decryption:
// explicitly given ones, else the AV_IDENTITY* environment variables, else
// the default key locations. It is shared by the CLI and the av library.
package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/oneryx/av/internal/crypt"
)

const (
	// FilesEnv lists identity files, separated like $PATH.
	FilesEnv = "AV_IDENTITY"
	// DataEnv holds identity content directly, e.g. a CI secret.
	DataEnv = "AV_IDENTITY_DATA"
)

// DefaultPaths returns the identity files tried when nothing else is given.
func DefaultPaths() []string {
	var paths []string
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		paths = append(paths, filepath.Join(x, "age", "keys.txt"))
	}
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

// Load returns the identities in files and data if either is given. Otherwise
// it uses $AV_IDENTITY_DATA and $AV_IDENTITY, and if those are unset too, the
// DefaultPaths. Only the default paths may be missing or invalid; they are
// then skipped silently. prompt is asked for passphrases of protected keys.
func Load(files []string, data []byte, prompt crypt.SecretPrompt) ([]crypt.Identity, error) {
	if len(files) > 0 || len(data) > 0 {
		return load("identity data", data, files, prompt)
	}
	envFiles, envData := os.Getenv(FilesEnv), os.Getenv(DataEnv)
	if envFiles == "" && envData == "" {
		return loadFiles(DefaultPaths(), false, prompt)
	}
	var list []string
	if envFiles != "" {
		list = filepath.SplitList(envFiles)
	}
	ids, err := load("$"+DataEnv, []byte(envData), nil, prompt)
	if err != nil {
		return nil, err
	}
	got, err := loadFiles(list, true, prompt)
	if err != nil {
		return nil, fmt.Errorf("$%s: %v", FilesEnv, err)
	}
	return append(ids, got...), nil
}

func load(source string, data []byte, files []string, prompt crypt.SecretPrompt) ([]crypt.Identity, error) {
	var ids []crypt.Identity
	if len(data) > 0 {
		got, err := crypt.ParseIdentityData(source, data, prompt)
		if err != nil {
			return nil, err
		}
		ids = append(ids, got...)
	}
	got, err := loadFiles(files, true, prompt)
	if err != nil {
		return nil, err
	}
	return append(ids, got...), nil
}

func loadFiles(paths []string, strict bool, prompt crypt.SecretPrompt) ([]crypt.Identity, error) {
	var ids []crypt.Identity
	seen := map[string]bool{}
	for _, p := range paths {
		if abs, err := filepath.Abs(p); err == nil {
			if seen[abs] {
				continue
			}
			seen[abs] = true
		}
		got, err := crypt.LoadIdentityFile(p, prompt)
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
