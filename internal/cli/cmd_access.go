package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/oneryx/av/internal/crypt"
	"github.com/spf13/cobra"
)

// Commands that change who can decrypt a file.

func (c *CLI) recipientsCmd() *cobra.Command {
	var o options
	list := func(*cobra.Command, []string) error {
		lines, err := readSidecar(EncPath(o.file))
		if err != nil {
			return err
		}
		for _, l := range lines {
			fmt.Fprintln(c.Stdout, l)
		}
		return nil
	}
	cmd := &cobra.Command{
		Use:   "recipients",
		Short: "List, add or remove the recipients of a file",
		Long: `List the recipients in <file>.recipients (the default), or add or remove
some and re-encrypt the file.

Removed recipients can still read old copies of the file (e.g. in git
history), so rotate the secrets they had access to.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown action %q", args[0])
			}
			return nil
		},
		RunE: list,
	}
	addFileFlag(cmd.PersistentFlags(), &o)
	addIdentityFlag(cmd.PersistentFlags(), &o)
	registerCompletions(cmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the recipients",
		Args:  noArgs,
		RunE:  list,
	}, &cobra.Command{
		Use:     "add RECIPIENT...",
		Short:   "Add recipients and re-encrypt",
		Example: `  av recipients add age1... "ssh-ed25519 AAAA... alice"`,
		Args:    minArgs(1, "at least one RECIPIENT"),
		RunE: func(_ *cobra.Command, args []string) error {
			return c.changeRecipients(&o, func(lines []string) ([]string, error) {
				for _, r := range args {
					if _, err := crypt.ParseRecipient(r); err != nil {
						return nil, fmt.Errorf("invalid recipient %q: %v", r, err)
					}
				}
				return dedupe(append(append([]string{}, lines...), args...)), nil
			})
		},
	}, &cobra.Command{
		Use:   "rm RECIPIENT...",
		Short: "Remove recipients and re-encrypt",
		Long: `Remove recipients and re-encrypt. A RECIPIENT may be the full line, an SSH
key without its comment, or just the SSH comment (e.g. "alice").`,
		Args: minArgs(1, "at least one RECIPIENT"),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			lines, _ := crypt.ReadRecipientsFile(sidecarPath(EncPath(o.file)))
			return recipientNames(lines), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if err := c.changeRecipients(&o, func(lines []string) ([]string, error) {
				return removeRecipients(lines, args, EncPath(o.file))
			}); err != nil {
				return err
			}
			fmt.Fprintln(c.Stderr, "Removed recipients can still read old copies (e.g. in git history); rotate the secrets they had access to.")
			return nil
		},
	})
	return cmd
}

// changeRecipients rewrites the recipients file with edit's result and
// re-encrypts the file for it.
func (c *CLI) changeRecipients(o *options, edit func([]string) ([]string, error)) error {
	path := EncPath(o.file)
	lines, err := readSidecar(path)
	if err != nil {
		return err
	}
	updated, err := edit(lines)
	if err != nil {
		return err
	}
	if strings.Join(updated, "\n") == strings.Join(lines, "\n") {
		fmt.Fprintln(c.Stderr, "Recipients unchanged; nothing written.")
		return nil
	}
	resolve := func(crypt.Info) (target, bool, error) {
		t, err := recipientsTarget(updated, true)
		return t, true, err
	}
	return c.update(o, path, resolve, unchanged)
}

func removeRecipients(lines, args []string, path string) ([]string, error) {
	drop := map[string]bool{}
	for _, arg := range args {
		var matches []string
		for _, l := range lines {
			if matchRecipient(l, arg) {
				matches = append(matches, l)
			}
		}
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("%q is not a recipient of %s", arg, path)
		case 1:
			drop[matches[0]] = true
		default:
			return nil, fmt.Errorf("%q matches %d recipients; use the full key", arg, len(matches))
		}
	}
	var out []string
	for _, l := range lines {
		if !drop[l] {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("can't remove every recipient")
	}
	return out, nil
}

// recipientNames returns the short names "rm" accepts, for completion: the
// SSH comment if there is one, otherwise the whole recipient.
func recipientNames(lines []string) []string {
	var names []string
	for _, l := range lines {
		if f := strings.Fields(l); len(f) >= 3 {
			names = append(names, strings.Join(f[2:], " "))
		} else {
			names = append(names, l)
		}
	}
	return names
}

func (c *CLI) rekeyCmd() *cobra.Command {
	var o options
	return readCmd(&o, &cobra.Command{
		Use:   "rekey",
		Short: "Re-encrypt a file for its current recipients",
		Long: `Re-encrypt the file for the recipients in <file>.recipients (or with its
passphrase), e.g. after pulling a recipients file a teammate changed.`,
		Args: noArgs,
		RunE: func(*cobra.Command, []string) error {
			path := EncPath(o.file)
			return c.update(&o, path, keepTarget(path, true), unchanged)
		},
	})
}
