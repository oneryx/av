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
	"github.com/oneryx/av/internal/tty"
)

// target describes how a file will be encrypted when saved.
type target struct {
	recipients []age.Recipient
	// lines are the recipient strings, or nil for a passphrase.
	lines []string
	// writeSidecar records lines in <file>.recipients on save.
	writeSidecar bool
}

func (t target) isPassphrase() bool { return t.lines == nil }

func sidecarPath(encPath string) string { return encPath + ".recipients" }

func recipientsTarget(lines []string, writeSidecar bool) (target, error) {
	recs, err := crypt.ParseRecipients(lines)
	return target{recipients: recs, lines: lines, writeSidecar: writeSidecar}, err
}

func passphraseTarget(pass string) (target, error) {
	recs, err := crypt.PassphraseRecipient(pass)
	return target{recipients: recs}, err
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
	t, err = recipientsTarget(dedupe(lines), true)
	return t, true, err
}

// newTarget picks recipients for a new file: flags, then an existing
// recipients file (e.g. committed by a teammate), then the user's own key.
func (o *options) newTarget(path string, stdin io.Reader) (target, error) {
	if t, ok, err := o.explicitTarget(stdin); ok || err != nil {
		return t, err
	}
	if lines, err := crypt.ReadRecipientsFile(sidecarPath(path)); err == nil {
		return recipientsTarget(lines, false)
	}
	ids, err := o.loadIdentities()
	if err != nil {
		return target{}, err
	}
	for _, id := range ids {
		if id.Recipient != "" {
			return recipientsTarget([]string{id.Recipient}, true)
		}
	}
	return target{}, errors.New("no recipients: pass -r, -R or -p, or set up an identity (-i, AV_IDENTITY, ~/.config/age/keys.txt)")
}

// sameTarget re-encrypts an existing file the way it was: with its
// passphrase, or to the recipients in its recipients file.
func sameTarget(path string, info crypt.Info) (target, error) {
	if info.IsPassphrase() {
		return passphraseTarget(info.Passphrase)
	}
	lines, err := readSidecar(path)
	if err != nil {
		return target{}, err
	}
	return recipientsTarget(lines, false)
}

func readSidecar(path string) ([]string, error) {
	sc := sidecarPath(path)
	if _, err := os.Stat(sc); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("don't know who %s is encrypted for: %s not found; pass -r or -R to `av edit`", path, sc)
	}
	return crypt.ReadRecipientsFile(sc)
}

func writeSidecar(encPath string, lines []string) error {
	var b strings.Builder
	b.WriteString("# Recipients for " + filepath.Base(encPath) + ", managed by av. Safe to commit.\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return crypt.WriteFileAtomic(sidecarPath(encPath), []byte(b.String()), 0o644)
}

// save encrypts plain to path. The recipients file is updated first so that,
// if writing the encrypted file fails, the next save still uses the intended
// recipients rather than silently restoring old ones.
func (c *CLI) save(path string, plain []byte, t target) error {
	data, err := crypt.Encrypt(plain, t.recipients)
	if err != nil {
		return err
	}
	switch {
	case t.isPassphrase():
		if err := os.Remove(sidecarPath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	case t.writeSidecar:
		if err := writeSidecar(path, t.lines); err != nil {
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
