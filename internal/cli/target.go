package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/oneryx/av/internal/crypt"
)

// recipientsFileName is the recipients file: the public keys that files are
// encrypted to when no -r or -R is given. It is looked up in the working
// directory first, then in the age config directory (see findRecipients).
const recipientsFileName = "recipients.txt"

// target describes who a file will be encrypted to when saved.
type target struct {
	recipients []age.Recipient
	// lines are the recipient strings.
	lines []string
}

func recipientsTarget(lines []string) (target, error) {
	recs, err := crypt.ParseRecipients(lines)
	return target{recipients: recs, lines: lines}, err
}

// explicitTarget handles -r and -R. ok is false if neither was given. stdin
// is used for "-R -"; nil means stdin is not available.
func (o *options) explicitTarget(stdin io.Reader) (t target, ok bool, err error) {
	var lines []string
	for _, r := range o.recipients {
		if _, err := crypt.ParseRecipient(r); err != nil {
			return t, true, fmt.Errorf("invalid recipient %q: %v", r, err)
		}
		lines = append(lines, r)
	}
	for _, f := range o.recipientFiles {
		var got []string
		if f == "-" {
			if stdin == nil {
				return t, true, errors.New("-R - can't be used here because stdin is needed for something else")
			}
			got, err = crypt.ReadRecipients("stdin", stdin)
		} else {
			got, err = crypt.ReadRecipientsFile(f)
		}
		if err != nil {
			return t, true, err
		}
		lines = append(lines, got...)
	}
	if len(lines) == 0 {
		return t, false, nil
	}
	t, err = recipientsTarget(dedupe(lines))
	return t, true, err
}

// ownTarget encrypts to the public key of the first identity.
func (o *options) ownTarget() (target, error) {
	ids, err := o.loadIdentities()
	if err != nil {
		return target{}, err
	}
	for _, id := range ids {
		if id.Recipient != "" {
			return recipientsTarget([]string{id.Recipient})
		}
	}
	return target{}, errors.New("no recipients: pass -r or -R, create " + recipientsFileName + ", or set up an identity (-i or ~/.config/age/keys.txt)")
}

// configRecipientsPath is the recipients file in the age config directory, the
// same place identities are read from: ~/.config/age.
func configRecipientsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "age", recipientsFileName), nil
}

// findRecipients returns the default recipients file: ./recipients.txt if it
// exists, else the config directory's. ok is false if neither exists; path is
// then the working-directory name, where a new file is created.
func findRecipients() (path string, ok bool, err error) {
	if fileExists(recipientsFileName) {
		return recipientsFileName, true, nil
	}
	cfg, err := configRecipientsPath()
	if err != nil {
		return "", false, err
	}
	if fileExists(cfg) {
		return cfg, true, nil
	}
	return recipientsFileName, false, nil
}

// loadRecipients returns the lines of the default recipients file. found is
// false if there is no such file.
func loadRecipients() (lines []string, found bool, err error) {
	path, ok, err := findRecipients()
	if err != nil || !ok {
		return nil, false, err
	}
	lines, err = crypt.ReadRecipientsFile(path)
	return lines, true, err
}

// newTarget picks recipients for a file: flags, then the recipients file if
// there is one, then the user's own key. Existing files are re-encrypted this
// way too, so the save message always lists who the file is for now.
func (o *options) newTarget(stdin io.Reader) (target, error) {
	if t, ok, err := o.explicitTarget(stdin); ok || err != nil {
		return t, err
	}
	lines, found, err := loadRecipients()
	if err != nil {
		return target{}, err
	}
	if found {
		return recipientsTarget(lines)
	}
	return o.ownTarget()
}

// save encrypts plain to path and reports the recipients used.
func (c *CLI) save(path string, plain []byte, t target) error {
	data, err := crypt.Encrypt(plain, t.recipients)
	if err != nil {
		return err
	}
	if err := crypt.WriteFileAtomic(path, data, 0o600); err != nil {
		return err
	}
	// Always show who can decrypt, so an unexpected recipient (e.g. one added
	// to a shared recipients file) gets noticed.
	fmt.Fprintf(c.Stderr, "Wrote %s, encrypted to:\n", path)
	for _, l := range t.lines {
		fmt.Fprintf(c.Stderr, "    %s\n", shortRecipient(l))
	}
	return nil
}

// shortRecipient abbreviates long SSH keys for display.
func shortRecipient(s string) string {
	f := strings.Fields(s)
	if len(f) >= 2 && strings.HasPrefix(f[0], "ssh-") && len(f[1]) > 40 {
		f[1] = f[1][:16] + "…" + f[1][len(f[1])-8:]
	}
	return strings.Join(f, " ")
}
