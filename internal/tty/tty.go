// Package tty reads interactive input from the controlling terminal, so that
// prompts keep working when stdout is captured (e.g. eval "$(av export)").
package tty

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

func open() (*os.File, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("no terminal available for prompt: %w", err)
	}
	return f, nil
}

// ReadSecret prompts for a secret without echoing it.
func ReadSecret(prompt string) ([]byte, error) {
	f, err := open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fmt.Fprint(f, prompt+" ")
	defer fmt.Fprintln(f)
	return term.ReadPassword(int(f.Fd()))
}

// ReadNewPassphrase prompts for a new passphrase twice and checks they match.
func ReadNewPassphrase() (string, error) {
	p1, err := ReadSecret("Enter new passphrase:")
	if err != nil {
		return "", err
	}
	if len(p1) == 0 {
		return "", errors.New("passphrase must not be empty")
	}
	p2, err := ReadSecret("Confirm passphrase:")
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", errors.New("passphrases didn't match")
	}
	return string(p1), nil
}
