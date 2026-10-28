package av

import (
	"bytes"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

const content = "# comment\nFOO=bar\nexport QUOTED=\"a b\\nc\"\nEMPTY=\n"

var want = map[string]string{"FOO": "bar", "QUOTED": "a b\nc", "EMPTY": ""}

// setup isolates the test from the user's keys and environment and returns a
// fresh key, its file and a temp working directory.
func setup(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AV_IDENTITY", "")
	t.Setenv("AV_IDENTITY_DATA", "")
	key, err := age.GenerateX25519Identity()
	must(t, err)
	keyFile := filepath.Join(dir, "key.txt")
	must(t, os.WriteFile(keyFile, []byte(key.String()+"\n"), 0o600))
	return key, keyFile
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func encrypt(t *testing.T, path, plain string, r age.Recipient) {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	must(t, err)
	_, err = w.Write([]byte(plain))
	must(t, err)
	must(t, w.Close())
	must(t, os.WriteFile(path, buf.Bytes(), 0o600))
}

func check(t *testing.T, got map[string]string, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReadIdentitySources(t *testing.T) {
	t.Run("identity files option, default path", func(t *testing.T) {
		key, keyFile := setup(t)
		encrypt(t, DefaultPath, content, key.Recipient())
		got, err := Read("", WithIdentityFiles(keyFile))
		check(t, got, err)
	})
	t.Run("identity data option", func(t *testing.T) {
		key, _ := setup(t)
		encrypt(t, "x.env.age", content, key.Recipient())
		got, err := Read("x.env.age", WithIdentityData([]byte(key.String())))
		check(t, got, err)
	})
	t.Run("AV_IDENTITY", func(t *testing.T) {
		key, keyFile := setup(t)
		encrypt(t, DefaultPath, content, key.Recipient())
		t.Setenv("AV_IDENTITY", keyFile)
		got, err := Read("")
		check(t, got, err)
	})
	t.Run("AV_IDENTITY_DATA", func(t *testing.T) {
		key, _ := setup(t)
		encrypt(t, DefaultPath, content, key.Recipient())
		t.Setenv("AV_IDENTITY_DATA", key.String())
		got, err := Read("")
		check(t, got, err)
	})
	t.Run("default key location", func(t *testing.T) {
		key, _ := setup(t)
		encrypt(t, DefaultPath, content, key.Recipient())
		home, _ := os.UserHomeDir()
		must(t, os.MkdirAll(filepath.Join(home, ".config", "age"), 0o700))
		must(t, os.WriteFile(filepath.Join(home, ".config", "age", "keys.txt"), []byte(key.String()), 0o600))
		got, err := Read("")
		check(t, got, err)
	})
	t.Run("options take precedence over env", func(t *testing.T) {
		key, keyFile := setup(t)
		encrypt(t, DefaultPath, content, key.Recipient())
		t.Setenv("AV_IDENTITY", "/does/not/exist")
		got, err := Read("", WithIdentityFiles(keyFile))
		check(t, got, err)
	})
}

func TestReadErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		setup(t)
		_, err := Read("")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("got %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("no identity", func(t *testing.T) {
		key, _ := setup(t)
		encrypt(t, DefaultPath, content, key.Recipient())
		_, err := Read("")
		if !errors.Is(err, ErrNoIdentity) {
			t.Fatalf("got %v, want ErrNoIdentity", err)
		}
	})
	t.Run("wrong identity", func(t *testing.T) {
		key, _ := setup(t)
		other, err := age.GenerateX25519Identity()
		must(t, err)
		encrypt(t, DefaultPath, content, key.Recipient())
		if _, err := Read("", WithIdentityData([]byte(other.String()))); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("missing identity file", func(t *testing.T) {
		key, _ := setup(t)
		encrypt(t, DefaultPath, content, key.Recipient())
		if _, err := Read("", WithIdentityFiles("nope.txt")); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("invalid content", func(t *testing.T) {
		key, keyFile := setup(t)
		encrypt(t, DefaultPath, "FOO=1\nSECRET=\"hunter2\n", key.Recipient())
		_, err := Read("", WithIdentityFiles(keyFile))
		if err == nil || !strings.Contains(err.Error(), "line 2: unterminated double quote") {
			t.Fatalf("got %v, want invalid line error", err)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("error leaks the value: %v", err)
		}
	})
	t.Run("duplicate keys", func(t *testing.T) {
		key, keyFile := setup(t)
		encrypt(t, DefaultPath, "FOO=1\nFOO=2\n", key.Recipient())
		if _, err := Read("", WithIdentityFiles(keyFile)); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestReadPassphrase(t *testing.T) {
	setup(t)
	r, err := age.NewScryptRecipient("secret")
	must(t, err)
	r.SetWorkFactor(10)
	encrypt(t, DefaultPath, content, r)

	if _, err := Read(""); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("no passphrase: got %v, want ErrPassphraseRequired", err)
	}
	got, err := Read("", WithPassphrase("secret"))
	check(t, got, err)

	var asked string
	got, err = Read("", WithPrompt(func(p string) ([]byte, error) {
		asked = p
		return []byte("secret"), nil
	}))
	check(t, got, err)
	if asked == "" {
		t.Error("prompt was not called")
	}

	if _, err := Read("", WithPassphrase("wrong")); err == nil || !strings.Contains(err.Error(), "incorrect passphrase") {
		t.Fatalf("wrong passphrase: got %v", err)
	}
}

func TestLoad(t *testing.T) {
	key, keyFile := setup(t)
	encrypt(t, DefaultPath, content, key.Recipient())
	t.Setenv("FOO", "from-env")
	t.Setenv("QUOTED", "")
	os.Unsetenv("QUOTED")
	t.Setenv("EMPTY", "")
	os.Unsetenv("EMPTY")

	must(t, Load("", WithIdentityFiles(keyFile)))
	if got := os.Getenv("FOO"); got != "from-env" {
		t.Errorf("FOO = %q, want the existing value kept", got)
	}
	if got := os.Getenv("QUOTED"); got != "a b\nc" {
		t.Errorf("QUOTED = %q", got)
	}
	if got, ok := os.LookupEnv("EMPTY"); !ok || got != "" {
		t.Errorf("EMPTY = %q, %v; want set to empty", got, ok)
	}
}
