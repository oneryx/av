// Package crypt wraps the age library for encrypting and decrypting files.
package crypt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// ErrNoIdentity is returned when a recipient-encrypted file is decrypted
// without any identities.
var ErrNoIdentity = errors.New("no identity found")

// Decrypt decrypts an age file with the identities returned by loadIDs. The
// identities are loaded only when needed. ASCII-armored files (as written by
// "age -a") are still read so they can be converted on the next save.
func Decrypt(data []byte, loadIDs func() ([]age.Identity, error)) ([]byte, error) {
	var r io.Reader = bytes.NewReader(data)
	if trimmed := bytes.TrimSpace(data); bytes.HasPrefix(trimmed, []byte(armor.Header)) {
		r = armor.NewReader(bytes.NewReader(trimmed))
	}
	br := bufio.NewReader(r)
	if isScrypt(br) {
		return nil, errors.New("encrypted with a passphrase, which av does not support")
	}

	ids, err := loadIDs()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, ErrNoIdentity
	}
	plain, err := decryptAll(br, ids...)
	if errors.As(err, new(*age.NoIdentityMatchError)) {
		return nil, errors.New("no identity matched any of the file's recipients")
	}
	return plain, err
}

func decryptAll(r io.Reader, ids ...age.Identity) ([]byte, error) {
	d, err := age.Decrypt(r, ids...)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	plain, err := io.ReadAll(d)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return plain, nil
}

// isScrypt peeks at the age header to check whether the first stanza is an
// scrypt (passphrase) stanza.
func isScrypt(br *bufio.Reader) bool {
	p, _ := br.Peek(64)
	_, rest, ok := bytes.Cut(p, []byte("\n"))
	return ok && bytes.HasPrefix(rest, []byte("-> scrypt "))
}

// Encrypt encrypts plain to the given recipients.
func Encrypt(plain []byte, recipients []age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients specified")
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteFileAtomic writes data to name via a temporary file and rename. If name
// is a symlink, its target is replaced and the link is kept.
func WriteFileAtomic(name string, data []byte, perm os.FileMode) error {
	if resolved, err := filepath.EvalSymlinks(name); err == nil {
		name = resolved
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".av-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}
