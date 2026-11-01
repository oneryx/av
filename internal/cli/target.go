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
	"github.com/oneryx/av/internal/identity"
	"github.com/oneryx/av/internal/tty"
)

const (
	// recipientsName is the default recipients file name.
	recipientsName = "recipients.txt"
	// recipientsEnv names the recipients file to use when --recipients-path
	// is not given.
	recipientsEnv = "AV_RECIPIENTS"
)

// target describes how a file will be encrypted when saved.
type target struct {
	recipients []age.Recipient
	// lines are the recipient strings, or nil for a passphrase.
	lines []string
	// writeTo is the recipients file rewritten on save, or "" to leave it alone.
	writeTo string
}

func (t target) isPassphrase() bool { return t.lines == nil }

func recipientsTarget(lines []string, writeTo string) (target, error) {
	recs, err := crypt.ParseRecipients(lines)
	return target{recipients: recs, lines: lines, writeTo: writeTo}, err
}

func passphraseTarget(pass string) (target, error) {
	recs, err := crypt.PassphraseRecipient(pass)
	return target{recipients: recs}, err
}

// recipientsFile returns the recipients file to use and whether it exists.
// It is --recipients-path, else $AV_RECIPIENTS, else the first recipients.txt
// in the current directory or next to a default keys.txt. If none exists the
// path is ./recipients.txt, which a save creates.
func (o *options) recipientsFile() (string, bool) {
	for _, p := range []string{o.recipientsPath, os.Getenv(recipientsEnv)} {
		if p != "" {
			return p, fileExists(p)
		}
	}
	for _, p := range recipientsSearch() {
		if fileExists(p) {
			return p, true
		}
	}
	return recipientsName, false
}

// recipientsSearch lists where recipients.txt is looked for, in order: the
// current directory, then the directories of the default keys.txt files.
func recipientsSearch() []string {
	dirs := []string{"."}
	for _, p := range identity.DefaultPaths() {
		if filepath.Base(p) == "keys.txt" {
			dirs = append(dirs, filepath.Dir(p))
		}
	}
	var out []string
	for _, d := range dirs {
		out = append(out, filepath.Join(d, recipientsName))
	}
	return out
}

// readRecipients returns the recipient lines of the recipients file and its path.
func (o *options) readRecipients() ([]string, string, error) {
	path, err := o.existingRecipientsFile()
	if err != nil {
		return nil, path, err
	}
	lines, err := crypt.ReadRecipientsFile(path)
	return lines, path, err
}

// existingRecipientsFile returns the recipients file path, or an error if it does not exist.
func (o *options) existingRecipientsFile() (string, error) {
	path, found := o.recipientsFile()
	if !found {
		return path, fmt.Errorf("no recipients file: %s not found; pass -r or -R", path)
	}
	return path, nil
}

// explicitTarget handles -p, -r and -R. ok is false if none were given.
// stdin is used for "-R -"; nil means stdin is not available.
func (o *options) explicitTarget(stdin io.Reader) (t target, ok bool, err error) {
	if o.passphrase {
		if len(o.recipients) > 0 || len(o.recipientFiles) > 0 {
			return t, true, errors.New("-p can't be combined with -r or -R")
		}
		pass, err := tty.ReadNewPassphrase()
		if err != nil {
			return t, true, err
		}
		t, err = passphraseTarget(pass)
		return t, true, err
	}
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
	path, _ := o.recipientsFile()
	t, err = recipientsTarget(dedupe(lines), path)
	return t, true, err
}

// newTarget picks recipients for a new file: flags, then the recipients file
// (e.g. committed by a teammate), then the user's own key.
func (o *options) newTarget(stdin io.Reader) (target, error) {
	if t, ok, err := o.explicitTarget(stdin); ok || err != nil {
		return t, err
	}
	if lines, _, err := o.readRecipients(); err == nil {
		return recipientsTarget(lines, "")
	}
	ids, err := o.loadIdentities()
	if err != nil {
		return target{}, err
	}
	path, _ := o.recipientsFile()
	for _, id := range ids {
		if id.Recipient != "" {
			return recipientsTarget([]string{id.Recipient}, path)
		}
	}
	return target{}, errors.New("no recipients: pass -r, -R or -p, or set up an identity (-i, AV_IDENTITY, ~/.config/age/keys.txt)")
}

// sameTarget re-encrypts an existing file the way it was: with its
// passphrase, or to the recipients file.
func (o *options) sameTarget(path string, info crypt.Info) (target, error) {
	if info.IsPassphrase() {
		return passphraseTarget(info.Passphrase)
	}
	lines, _, err := o.readRecipients()
	if err != nil {
		return target{}, fmt.Errorf("don't know who %s is encrypted for: %v", path, err)
	}
	return recipientsTarget(lines, "")
}

// writeRecipients writes the recipients file at path.
func writeRecipients(path string, lines []string) error {
	var b strings.Builder
	b.WriteString("# Recipients managed by av. Safe to commit.\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return crypt.WriteFileAtomic(path, []byte(b.String()), 0o644)
}

// save encrypts plain to path. The recipients file is updated first so that,
// if writing the encrypted file fails, the next save still uses the intended
// recipients rather than silently restoring old ones.
func (c *CLI) save(path string, plain []byte, t target) error {
	data, err := crypt.Encrypt(plain, t.recipients)
	if err != nil {
		return err
	}
	if t.writeTo != "" {
		if err := writeRecipients(t.writeTo, t.lines); err != nil {
			return err
		}
	}
	if err := crypt.WriteFileAtomic(path, data, 0o600); err != nil {
		return err
	}
	// Always show who can decrypt, so an unexpected recipient (e.g. one added
	// to a committed recipients file) gets noticed.
	if t.isPassphrase() {
		fmt.Fprintf(c.Stderr, "Wrote %s (passphrase-encrypted)\n", path)
		return nil
	}
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

// matchRecipient reports whether arg names the recipient line: the exact
// string, an SSH key with or without its comment, or just the SSH comment.
func matchRecipient(line, arg string) bool {
	if line == arg {
		return true
	}
	lf, af := strings.Fields(line), strings.Fields(arg)
	if len(lf) >= 2 && len(af) >= 2 && lf[0] == af[0] && lf[1] == af[1] {
		return true
	}
	return len(lf) >= 3 && strings.Join(lf[2:], " ") == arg
}
