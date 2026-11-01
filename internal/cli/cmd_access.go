package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oneryx/av/internal/crypt"
	"github.com/spf13/cobra"
)

// Commands that change who can decrypt a file.

// recipientsTemplate starts a new recipients file.
const recipientsTemplate = `# Public keys that av encrypts files to, one per line. Safe to commit.
# Example: av recipients edit, then add a line such as age1... or ssh-ed25519 AAAA... alice
`

func (c *CLI) recipientsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recipients",
		Short: "Get or edit the recipients file",
		Long: `The recipients file lists the public keys that files are encrypted to when
no -r or -R is given. Without FILE, it is recipients.txt in the current
directory, or else in ~/.config/age/.

"edit" does not re-encrypt any file: run "av edit" and save on each file afterwards.
Removed recipients can still read old copies of the file (e.g. in git
history), so rotate the secrets they had access to.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown action %q", args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprint(c.Stderr, cmd.UsageString())
			return exitCode(2)
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:               "get [FILE]",
		Short:             "Print the recipients",
		Args:              atMostOneFile,
		ValidArgsFunction: completeFile,
		RunE: func(_ *cobra.Command, args []string) error {
			path, found, err := recipientsPath(args)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("%s not found: create it with `av recipients edit`", path)
			}
			lines, err := crypt.ReadRecipientsFile(path)
			if err != nil {
				return err
			}
			for _, l := range lines {
				fmt.Fprintln(c.Stdout, l)
			}
			return nil
		},
	}, &cobra.Command{
		Use:   "edit [FILE]",
		Short: "Edit the recipients file in $EDITOR",
		Long: `Open the recipients file in $VISUAL/$EDITOR and save it when you quit. Every
non-comment line must be a valid recipient, and there must be at least one.
Nothing is re-encrypted; run "av edit" and save on the files that should change.`,
		Args:              atMostOneFile,
		ValidArgsFunction: completeFile,
		RunE: func(_ *cobra.Command, args []string) error {
			path, found, err := recipientsPath(args)
			if err != nil {
				return err
			}
			initial := []byte(recipientsTemplate)
			if found {
				if initial, err = os.ReadFile(path); err != nil {
					return err
				}
			}
			content, changed, err := c.editor(path).Edit(initial, validateRecipients)
			if err != nil {
				return err
			}
			if !changed {
				fmt.Fprintln(c.Stderr, "No changes made; nothing written.")
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := crypt.WriteFileAtomic(path, content, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(c.Stderr, "Wrote %s. Files are not re-encrypted: run av edit and save on them.\n", path)
			return nil
		},
	})
	return cmd
}

// atMostOneFile accepts an optional recipients FILE.
func atMostOneFile(_ *cobra.Command, args []string) error {
	if len(args) > 1 {
		return usagef("expected at most one FILE")
	}
	return nil
}

// recipientsPath returns the recipients file named by args, or the default
// one. found is false if the file does not exist.
func recipientsPath(args []string) (path string, found bool, err error) {
	if len(args) == 1 {
		return args[0], fileExists(args[0]), nil
	}
	return findRecipients()
}

// validateRecipients checks that content has at least one recipient and that
// every recipient line is valid.
func validateRecipients(content []byte) error {
	lines, err := crypt.ReadRecipients(recipientsFileName, bytes.NewReader(content))
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return errors.New("no recipients: add at least one public key")
	}
	_, err = crypt.ParseRecipients(lines)
	return err
}
