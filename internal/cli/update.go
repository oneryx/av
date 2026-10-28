package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"filippo.io/age"
	"github.com/oneryx/av/internal/crypt"
	"github.com/oneryx/av/internal/dotenv"
)

// update is the read-modify-write pipeline shared by every command that
// changes an existing file: it decrypts path, lets change produce new
// content, and re-encrypts it for the target returned by resolve. force saves
// even if the content is unchanged (e.g. when the recipients change). If the
// file is modified by someone else in the meantime, the user is asked before
// overwriting.
func (c *CLI) update(o *options, path string, resolve func(crypt.Info) (t target, force bool, err error), change func([]byte) ([]byte, bool, error)) error {
	plain, info, orig, err := o.decrypt(path)
	if err != nil {
		return err
	}
	t, force, err := resolve(info)
	if err != nil {
		return err
	}
	content, changed, err := change(plain)
	if err != nil {
		return err
	}
	if !changed && !force {
		fmt.Fprintln(c.Stderr, "No changes made; nothing written.")
		return nil
	}
	if now, err := os.ReadFile(path); err != nil || !bytes.Equal(now, orig) {
		if !c.confirm(fmt.Sprintf("%s was changed by someone else since it was decrypted. Overwrite those changes?", path)) {
			return fmt.Errorf("nothing written; %s was changed by someone else", path)
		}
	}
	return c.save(path, content, t)
}

// keepTarget is a resolve func for update that re-encrypts the file the way
// it already is.
func keepTarget(path string, force bool) func(crypt.Info) (target, bool, error) {
	return func(info crypt.Info) (target, bool, error) {
		t, err := sameTarget(path, info)
		return t, force, err
	}
}

func unchanged(plain []byte) ([]byte, bool, error) { return plain, false, nil }

func readEncrypted(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s does not exist (create it with `av new`)", path)
	}
	return data, err
}

// decrypt returns the plaintext, how it was encrypted, and the encrypted bytes.
func (o *options) decrypt(path string) ([]byte, crypt.Info, []byte, error) {
	data, err := readEncrypted(path)
	if err != nil {
		return nil, crypt.Info{}, nil, err
	}
	loadIDs := func() ([]age.Identity, error) {
		ids, err := o.loadIdentities()
		return crypt.AgeIdentities(ids), err
	}
	plain, info, err := crypt.Decrypt(data, loadIDs, readPrompt)
	if errors.Is(err, crypt.ErrNoIdentity) {
		return nil, info, nil, errors.New(noIdentityHint)
	}
	if err != nil {
		return nil, info, nil, fmt.Errorf("%s: %v", path, err)
	}
	return plain, info, data, nil
}

// entries decrypts and parses a file for print-like commands.
func (o *options) entries() ([]dotenv.Entry, error) {
	path := EncPath(o.file)
	plain, _, _, err := o.decrypt(path)
	if err != nil {
		return nil, err
	}
	entries, errs := dotenv.Parse(string(plain))
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s contains invalid lines (fix with `av edit`):\n%v", path, dotenv.ValidationError(errs))
	}
	return entries, nil
}
