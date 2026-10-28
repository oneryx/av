package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// options holds every flag; each command registers the subset it uses.
type options struct {
	file           string
	recipients     []string
	recipientFiles []string
	identities     []string
	passphrase     bool
	from           string
	force          bool
}

func addFileFlag(fs *pflag.FlagSet, o *options) {
	fs.StringVarP(&o.file, "file", "f", "", "encrypted `FILE` (default .env.age; -f prod means prod.env.age)")
}

func addIdentityFlag(fs *pflag.FlagSet, o *options) {
	fs.StringArrayVarP(&o.identities, "identity", "i", nil, "identity `PATH` for decryption (repeatable)")
}

func addRecipientFlags(fs *pflag.FlagSet, o *options, verb string) {
	fs.StringArrayVarP(&o.recipients, "recipient", "r", nil, verb+" to `RECIPIENT`: age1..., ssh-ed25519 or ssh-rsa (repeatable)")
	fs.StringArrayVarP(&o.recipientFiles, "recipients-file", "R", nil, verb+" to the recipients listed in `PATH`, - for stdin (repeatable)")
	fs.BoolVarP(&o.passphrase, "passphrase", "p", false, verb+" with a passphrase instead of recipients")
}

// registerCompletions sets up shell completion for whichever of the common
// flags cmd has.
func registerCompletions(cmd *cobra.Command) {
	if cmd.Flag("file") != nil {
		cmd.RegisterFlagCompletionFunc("file", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return []string{"age"}, cobra.ShellCompDirectiveFilterFileExt
		})
	}
}

// Positional argument checks that report usage errors.

func noArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usagef("unexpected argument %q (use -f to choose the file)", args[0])
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

// EncPath normalises a user-supplied path so it always ends in ".env.age".
//
//	""          -> .env.age
//	prod        -> prod.env.age
//	x.env       -> x.env.age
//	.env        -> .env.age
//	secrets.age -> secrets.env.age
func EncPath(p string) string {
	if p == "" {
		return ".env.age"
	}
	if strings.HasSuffix(p, ".env.age") {
		return p
	}
	p = strings.TrimSuffix(p, ".age")
	if base := filepath.Base(p); base == ".env" || strings.HasSuffix(base, ".env") {
		return p + ".age"
	}
	return p + ".env.age"
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
