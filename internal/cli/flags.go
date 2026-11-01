package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oneryx/av/internal/crypt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// options holds every flag; each command registers the subset it uses.
type options struct {
	file           string
	recipients     []string
	recipientFiles []string
	identities     []string
	force          bool

	// ids caches loadIdentities.
	ids       []crypt.Identity
	idsLoaded bool
}

func addIdentityFlag(fs *pflag.FlagSet, o *options) {
	fs.StringArrayVarP(&o.identities, "identity", "i", nil, "identity `PATH` for decryption (repeatable)")
}

func addRecipientFlags(fs *pflag.FlagSet, o *options, verb string) {
	fs.StringArrayVarP(&o.recipients, "recipient", "r", nil, verb+" to `RECIPIENT`: age1..., ssh-ed25519 or ssh-rsa (repeatable)")
	fs.StringArrayVarP(&o.recipientFiles, "recipients-file", "R", nil, verb+" to the recipients listed in `PATH`, - for stdin (repeatable)")
}

// The encrypted file is the last argument. Commands that take nothing else
// accept any name for it (prod means prod.env.age). Commands that take keys
// or a command accept only a name ending in ".age" with no "=", so that keys
// (KEY, KEY=VALUE) are never mistaken for a file. Keys can't contain dots.

// fileArg splits the file off the end of args and returns the rest and the
// file name ("" if there is none).
func fileArg(args []string, anyName bool) ([]string, string) {
	n := len(args)
	if n == 0 {
		return args, ""
	}
	last := args[n-1]
	if strings.Contains(last, "=") || (!anyName && !strings.HasSuffix(last, ".age")) {
		return args, ""
	}
	return args[:n-1], last
}

// takeFile sets o.file from the trailing argument and returns the rest.
func (o *options) takeFile(args []string, anyName bool) []string {
	rest, file := fileArg(args, anyName)
	o.file = file
	return rest
}

// withFile validates the arguments that come before the optional file.
func withFile(anyName bool, check cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		rest, _ := fileArg(args, anyName)
		return check(cmd, rest)
	}
}

// completeFile completes the encrypted file argument.
func completeFile(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return []string{"age"}, cobra.ShellCompDirectiveFilterFileExt
}

// Positional argument checks that report usage errors.

func noArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usagef("unexpected argument %q", args[0])
	}
	return nil
}

func exactArgs(n int, what string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != n {
			return usagef("expected %s", what)
		}
		return nil
	}
}

func minArgs(n int, what string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) < n {
			return usagef("expected %s", what)
		}
		return nil
	}
}

// EncPath normalises a user-supplied path to an encrypted file name. Paths
// ending in ".age" are kept as they are; anything else becomes an env file.
//
//	""          -> .env.age
//	prod        -> prod.env.age
//	x.env       -> x.env.age
//	.env        -> .env.age
//	secrets.age -> secrets.age (text file)
func EncPath(p string) string {
	switch {
	case p == "":
		return ".env.age"
	case strings.HasSuffix(p, ".age"):
		return p
	case strings.HasSuffix(filepath.Base(p), ".env"):
		return p + ".age"
	}
	return p + ".env.age"
}

// isEnvPath reports whether path is an env file (KEY=VALUE content). Other
// ".age" paths hold plain text.
func isEnvPath(path string) bool { return strings.HasSuffix(path, ".env.age") }

// requireEnv fails for text files, for commands that work on KEY=VALUE.
func requireEnv(path, command string) error {
	if isEnvPath(path) {
		return nil
	}
	return fmt.Errorf("%s is a text file; %s works only on *.env.age files", path, command)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
