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

// SecretPrompt asks the user for a secret. The argument is the prompt text.
type SecretPrompt func(prompt string) ([]byte, error)

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

// LoadIdentityFile loads the identities in an age identity file (optionally
// passphrase-encrypted) or an SSH private key. For encrypted SSH keys without
// an embedded public key, name+".pub" is consulted.
func LoadIdentityFile(name string, prompt SecretPrompt) ([]Identity, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity file: %v", err)
	}
	return parseIdentityData(name, data, readPubLine(name), prompt)
}

// ParseIdentityData parses identities given as content rather than a file,
// e.g. from an environment variable. source is used in messages only.
func ParseIdentityData(source string, data []byte, prompt SecretPrompt) ([]Identity, error) {
	return parseIdentityData(source, data, "", prompt)
}

func parseIdentityData(name string, data []byte, pubLine string, prompt SecretPrompt) ([]Identity, error) {
	trimmed := bytes.TrimSpace(data)

	switch {
	// A passphrase-encrypted age identity file, plain or armored.
	case bytes.HasPrefix(trimmed, []byte("age-encryption")) || bytes.HasPrefix(trimmed, []byte(armor.Header)):
		var r io.Reader = bytes.NewReader(trimmed)
		if bytes.HasPrefix(trimmed, []byte(armor.Header)) {
			r = armor.NewReader(bytes.NewReader(trimmed))
		}
		pass, err := prompt(fmt.Sprintf("Enter passphrase for identity file %q:", name))
		if err != nil {
			return nil, err
		}
		sid, err := age.NewScryptIdentity(string(pass))
		if err != nil {
			return nil, err
		}
		d, err := age.Decrypt(r, sid)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt identity file %q: %v", name, err)
		}
		plain, err := io.ReadAll(d)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt identity file %q: %v", name, err)
		}
		return parseAgeIdentities(name, plain)

	// An SSH private key.
	case bytes.HasPrefix(trimmed, []byte("-----BEGIN")):
		return parseSSHIdentity(name, trimmed, pubLine, prompt)

	default:
		return parseAgeIdentities(name, data)
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

func parseSSHIdentity(name string, pemBytes []byte, pubLine string, prompt SecretPrompt) ([]Identity, error) {
	id, err := agessh.ParseIdentity(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		pubKey := missing.PublicKey
		if pubKey == nil {
			if pubLine == "" {
				return nil, fmt.Errorf("failed to obtain public key for SSH key %q: ensure %q exists", name, name+".pub")
			}
			pubKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(pubLine))
			if err != nil {
				return nil, fmt.Errorf("failed to parse %q: %v", name+".pub", err)
			}
		}
		if pubLine == "" {
			pubLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
		}
		eid, err := agessh.NewEncryptedSSHIdentity(pubKey, pemBytes, func() ([]byte, error) {
			return prompt(fmt.Sprintf("Enter passphrase for %q:", name))
		})
		if err != nil {
			return nil, err
		}
		return []Identity{{Identity: eid, Recipient: pubLine, Source: name}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
	}
	if pubLine == "" {
		pubLine = sshRecipientFromPrivate(pemBytes)
	}
	return []Identity{{Identity: id, Recipient: pubLine, Source: name}}, nil
}

func readPubLine(name string) string {
	data, err := os.ReadFile(name + ".pub")
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(data)), "\n")
	if _, err := agessh.ParseRecipient(line); err != nil {
		return ""
	}
	return line
}

func sshRecipientFromPrivate(pemBytes []byte) string {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}
