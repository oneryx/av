// Package cli implements the av command line on top of cobra.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// CLI holds the process streams and build version.
type CLI struct {
	Version string
	// Stdin answers interactive questions and is passed to `av run`; the
	// editor itself and secret prompts use the terminal.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	in *bufio.Reader
}

// exitCode is returned by commands that set the exit status themselves.
// Nothing more is printed for it.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// usageError is a command line mistake: it is printed with the command's
// usage and exits with status 2.
type usageError struct{ error }

func usagef(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

// Main runs av with os.Args and returns the process exit code.
func Main(version string) int {
	c := &CLI{Version: version, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	return c.Run(os.Args[1:])
}

// Run executes a subcommand and returns the exit code.
func (c *CLI) Run(args []string) int {
	root := c.rootCmd()
	root.SetArgs(args)
	cmd, err := root.ExecuteC()

	var code exitCode
	var uerr usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &code):
		return int(code)
	case errors.As(err, &uerr):
		fmt.Fprintf(c.Stderr, "av: %v\n\n%s", uerr.error, cmd.UsageString())
		return 2
	default:
		fmt.Fprintf(c.Stderr, "av: %v\n", err)
		return 1
	}
}

const rootLong = `av (age-env) keeps .env files encrypted with age.

Identities:
    Without -i, av uses $AV_IDENTITY_DATA (the content of an identity file,
    handy in CI) and $AV_IDENTITY (identity file paths separated by ":") if
    set, otherwise any of ~/.config/age/keys.txt,
    ~/Library/Application Support/age/keys.txt (macOS), ~/.ssh/id_ed25519 and
    ~/.ssh/id_rsa that exist.

Recipients:
    Recipients used with av new / av edit are saved next to the encrypted
    file as <file>.recipients (public keys only, safe to commit), and reused
    by later edits. Every save prints who the file is encrypted to.
    Passphrase-encrypted files keep their passphrase on edit.

Using the variables:
    av run -- npm start           # only the command sees the variables
    eval "$(av export)"           # export them into the current shell

    Or add this function to ~/.zshrc or ~/.bashrc so "av export" works directly:
    av() { if [ "$1" = export ]; then eval "$(command av "$@")"; else command av "$@"; fi; }

Shell completion:
    source <(av completion zsh)   # see "av completion --help"`

const rootExample = `  av new                                   # open $EDITOR, encrypt to your own key
  av new --from .env -r age1... -r age1... # encrypt an existing .env to two recipients
  av new -f prod -R team.txt               # prod.env.age for the keys in team.txt
  av edit
  av set DEBUG=1 API_KEY                   # API_KEY is read without echo
  av recipients add "ssh-ed25519 AAAA... alice"
  av print -i ~/.ssh/id_ed25519
  av run -f prod -- ./deploy.sh`

func (c *CLI) rootCmd() *cobra.Command {
	cobra.EnableCommandSorting = false
	root := &cobra.Command{
		Use:     "av",
		Short:   "Keep .env files encrypted with age",
		Long:    rootLong,
		Example: rootExample,
		Version: c.Version,
		// Only reached when no subcommand matched.
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown command %q", args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprint(c.Stderr, cmd.UsageString())
			return exitCode(2)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetIn(c.Stdin)
	root.SetOut(c.Stdout)
	root.SetErr(c.Stderr)
	root.SetVersionTemplate("av {{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })
	root.SetHelpCommand(c.helpCmd())

	root.AddGroup(
		&cobra.Group{ID: "edit", Title: "Create and change files:"},
		&cobra.Group{ID: "use", Title: "Use the variables:"},
		&cobra.Group{ID: "access", Title: "Manage access:"},
	)
	add := func(group string, cmds ...*cobra.Command) {
		for _, cmd := range cmds {
			cmd.GroupID = group
			root.AddCommand(cmd)
		}
	}
	add("edit", c.newCmd(), c.editCmd(), c.setCmd(), c.unsetCmd())
	add("use", c.printCmd(), c.getCmd(), c.exportCmd(), c.runCmd())
	add("access", c.recipientsCmd(), c.rekeyCmd())
	root.AddCommand(c.versionCmd())
	return root
}

// helpCmd replaces cobra's help command so unknown topics are an error.
func (c *CLI) helpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "help [command]",
		Short: "Help about any command",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, rest, err := cmd.Root().Find(args)
			if err != nil || len(rest) > 0 {
				return usagef("unknown command %q", strings.Join(args, " "))
			}
			return target.Help()
		},
	}
}

func (c *CLI) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  noArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(c.Stdout, "av %s\n", c.Version)
		},
	}
}

// input returns Stdin as a shared buffered reader, so successive prompts
// (including the editor's) don't lose buffered input.
func (c *CLI) input() *bufio.Reader {
	if c.in == nil {
		c.in = bufio.NewReader(c.Stdin)
	}
	return c.in
}

// confirm asks a yes/no question on Stdin; anything but yes means no.
func (c *CLI) confirm(question string) bool {
	fmt.Fprintf(c.Stderr, "%s [y/N] ", question)
	line, _ := c.input().ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}
