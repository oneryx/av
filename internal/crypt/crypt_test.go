package crypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
)

const plain = "KEY1=VALUE1\nKEY2=VALUE2\n"

func ids(list ...age.Identity) func() ([]age.Identity, error) {
	return func() ([]age.Identity, error) { return list, nil }
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func roundTrip(t *testing.T, recs []age.Recipient, load func() ([]age.Identity, error)) {
	t.Helper()
	enc, err := Encrypt([]byte(plain), recs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(enc, load)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plain {
		t.Fatalf("got %q", got)
	}
}

func TestX25519MultipleRecipients(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	recs, err := ParseRecipients([]string{a.Recipient().String(), b.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, recs, ids(a))
	roundTrip(t, recs, ids(b))
	other, _ := age.GenerateX25519Identity()
	enc, _ := Encrypt([]byte(plain), recs)
	if _, err := Decrypt(enc, ids(other)); err == nil {
		t.Fatal("decrypted with wrong identity")
	}
	if _, err := Decrypt(enc, ids()); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
}

// Passphrase-encrypted files are rejected before any identity is loaded.
func TestPassphraseFileRejected(t *testing.T) {
	r, err := age.NewScryptRecipient("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(10)
	enc, err := Encrypt([]byte(plain), []age.Recipient{r})
	if err != nil {
		t.Fatal(err)
	}
	noIDs := func() ([]age.Identity, error) { t.Fatal("identities loaded for scrypt file"); return nil, nil }
	if _, err := Decrypt(enc, noIDs); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("err = %v", err)
	}
}

func TestIdentityFileAndRecipientsFile(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	idFile := writeFile(t, "keys.txt", "# created: now\n# public key: "+a.Recipient().String()+"\n"+a.String()+"\n")
	recFile := writeFile(t, "recipients.txt", "# team\n\n"+a.Recipient().String()+"\n"+b.Recipient().String()+"\n")

	loaded, err := LoadIdentityFile(idFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Recipient != a.Recipient().String() {
		t.Fatalf("loaded = %+v", loaded)
	}
	lines, err := ReadRecipientsFile(recFile)
	if err != nil || len(lines) != 2 {
		t.Fatalf("lines = %v, err = %v", lines, err)
	}
	recs, _ := ParseRecipients(lines)
	roundTrip(t, recs, ids(AgeIdentities(loaded)...))

	fromData, err := ParseIdentityData("identity data", []byte(a.String()))
	if err != nil || len(fromData) != 1 || fromData[0].Recipient != a.Recipient().String() {
		t.Fatalf("ParseIdentityData = %+v, %v", fromData, err)
	}

	if _, err := ReadRecipientsFile(idFile); err == nil || !strings.Contains(err.Error(), "apparent identity") {
		t.Fatalf("identity file accepted as recipients file: %v", err)
	}
}

func TestSSHEd25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	keyFile := writeFile(t, "id_ed25519", string(pem.EncodeToMemory(block)))

	loaded, err := LoadIdentityFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Recipient != pubLine {
		t.Fatalf("recipient = %q, want %q", loaded[0].Recipient, pubLine)
	}
	recs, err := ParseRecipients([]string{pubLine + " user@host"})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, recs, ids(AgeIdentities(loaded)...))

	// The same key given as data, e.g. from a secret manager.
	fromData, err := ParseIdentityData("identity data", pem.EncodeToMemory(block))
	if err != nil || len(fromData) != 1 || fromData[0].Recipient != pubLine {
		t.Fatalf("ParseIdentityData = %+v, %v", fromData, err)
	}
}

// Passphrase-protected SSH keys are rejected.
func TestEncryptedSSHKeyRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte("sshpass"))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := writeFile(t, "id_ed25519", string(pem.EncodeToMemory(block)))
	if _, err := LoadIdentityFile(keyFile); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRecipientRejects(t *testing.T) {
	for _, s := range []string{"", "nope", "AGE-SECRET-KEY-1ABC", "age1yubikey1qwerty"} {
		if _, err := ParseRecipient(s); err == nil {
			t.Errorf("ParseRecipient(%q) succeeded", s)
		}
	}
}

// Files written by "age -a" can still be read.
func TestDecryptArmored(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, _ := age.Encrypt(aw, a.Recipient())
	w.Write([]byte(plain))
	w.Close()
	aw.Close()
	got, err := Decrypt(buf.Bytes(), ids(a))
	if err != nil || string(got) != plain {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out")
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != "two" || fi.Mode().Perm() != 0o600 {
		t.Fatalf("content %q mode %v", b, fi.Mode())
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("leftover temp files: %v", entries)
	}
}

func TestWriteFileAtomicKeepsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	os.WriteFile(target, []byte("one"), 0o600)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(link, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink replaced by a regular file")
	}
	if b, _ := os.ReadFile(target); string(b) != "two" {
		t.Fatalf("target = %q", b)
	}
}
