package crypt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"filippo.io/age/tag"
	"golang.org/x/crypto/ssh"
)

// ParseRecipient parses a recipient string the same way the age CLI does,
// except plugin recipients are not supported.
func ParseRecipient(s string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(s, "age1tag1") || strings.HasPrefix(s, "age1tagpq1"):
		return tag.ParseRecipient(s)
	case strings.HasPrefix(s, "age1pq1"):
		return age.ParseHybridRecipient(s)
	case strings.HasPrefix(s, "age1") && strings.Count(s, "1") > 1:
		return nil, fmt.Errorf("age plugin recipients are not supported")
	case strings.HasPrefix(s, "age1"):
		return age.ParseX25519Recipient(s)
	case strings.HasPrefix(s, "ssh-"):
		return agessh.ParseRecipient(s)
	}
	return nil, fmt.Errorf("unknown recipient type: %q", s)
}

// ReadRecipientsFile reads a recipients file (one recipient per line, "#"
// comments and blank lines ignored) and returns the validated recipient lines.
func ReadRecipientsFile(name string) ([]string, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open recipients file: %v", err)
	}
	defer f.Close()
	return ReadRecipients(name, f)
}

// ReadRecipients is like ReadRecipientsFile but reads from r. name is used in
// messages only.
func ReadRecipients(name string, r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(io.LimitReader(r, 16<<20))
	n := 0
	for scanner.Scan() {
		n++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("%q: recipients file is not valid UTF-8", name)
		}
		if _, err := ParseRecipient(line); err != nil {
			if strings.HasPrefix(line, "AGE-") {
				return nil, fmt.Errorf("%q: line %d: apparent identity found in recipients file", name, n)
			}
			// Don't echo the line: it may be confidential.
			return nil, fmt.Errorf("%q: malformed recipient at line %d", name, n)
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%q: failed to read recipients file: %v", name, err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("%q: no recipients found", name)
	}
	return lines, nil
}

// ParseRecipients parses recipient strings.
func ParseRecipients(lines []string) ([]age.Recipient, error) {
	recs := make([]age.Recipient, 0, len(lines))
	for _, l := range lines {
		r, err := ParseRecipient(l)
		if err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// Identity is a loaded identity together with its public recipient string.
type Identity struct {
	age.Identity
	// Recipient is the public key in recipient syntax, or "" if unknown.
	Recipient string
	Source    string
}

// AgeIdentities turns identities into the plain age.Identity slice.
func AgeIdentities(ids []Identity) []age.Identity {
	out := make([]age.Identity, len(ids))
	for i, id := range ids {
		out[i] = id.Identity
	}
	return out
}

// LoadIdentityFile loads the identities in an age identity file or an SSH
// private key. Passphrase-protected files are an error.
func LoadIdentityFile(name string) ([]Identity, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity file: %v", err)
	}
	return ParseIdentityData(name, data)
}

// ParseIdentityData parses identities given as content rather than a file,
// e.g. from a secret manager. source is used in messages only.
func ParseIdentityData(source string, data []byte) ([]Identity, error) {
	trimmed := bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(trimmed, []byte("age-encryption")) || bytes.HasPrefix(trimmed, []byte(armor.Header)):
		return nil, fmt.Errorf("%q is encrypted with a passphrase, which av does not support", source)
	case bytes.HasPrefix(trimmed, []byte("-----BEGIN")):
		return parseSSHIdentity(source, trimmed)
	default:
		return parseAgeIdentities(source, data)
	}
}

func parseAgeIdentities(name string, data []byte) ([]Identity, error) {
	parsed, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name, err)
	}
	ids := make([]Identity, 0, len(parsed))
	for _, id := range parsed {
		var rec string
		switch id := id.(type) {
		case *age.X25519Identity:
			rec = id.Recipient().String()
		case *age.HybridIdentity:
			rec = id.Recipient().String()
		}
		ids = append(ids, Identity{Identity: id, Recipient: rec, Source: name})
	}
	return ids, nil
}

func parseSSHIdentity(name string, pemBytes []byte) ([]Identity, error) {
	id, err := agessh.ParseIdentity(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, fmt.Errorf("%q is passphrase-protected, which av does not support", name)
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
	}
	return []Identity{{Identity: id, Recipient: sshRecipientFromPrivate(pemBytes), Source: name}}, nil
}

func sshRecipientFromPrivate(pemBytes []byte) string {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}
