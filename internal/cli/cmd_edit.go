package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/oneryx/av/internal/crypt"
	"github.com/oneryx/av/internal/dotenv"
	"github.com/oneryx/av/internal/editor"
	"github.com/oneryx/av/internal/tty"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Commands that create or change the content of a file.

const newTemplate = `# One KEY=VALUE per line. Lines starting with # are comments.
# Values may be 'single' or "double" quoted. Example:
# DATABASE_URL=postgres://user:pass@localhost/db
`

func (c *CLI) editor() *editor.Editor {
	return &editor.Editor{Name: ".env", In: c.input(), Out: c.Stderr}
}

func (c *CLI) newCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a new encrypted .env.age file",
		Long: `Create an encrypted file. Without --from, $VISUAL/$EDITOR (default vi) is
opened on a template; the content must be valid KEY=VALUE lines to be saved.

Recipients are chosen from -r/-R, then an existing <file>.recipients, then
the public key of your identity. "-R -" (stdin) only works with --from.`,
		Args: noArgs,
		RunE: func(*cobra.Command, []string) error { return c.runNew(&o) },
	}
	fs := cmd.Flags()
	addFileFlag(fs, &o)
	fs.StringVar(&o.from, "from", "", "encrypt the existing plain .env file at `PATH` (left untouched)")
	fs.BoolVar(&o.force, "force", false, "overwrite an existing encrypted file")
	addRecipientFlags(fs, &o, "encrypt")
	addIdentityFlag(fs, &o)
	fs.Lookup("identity").Usage = "identity `PATH` whose public key is used when no recipients are given (repeatable)"
	registerCompletions(cmd)
	return cmd
}

func (c *CLI) runNew(o *options) error {
	path := EncPath(o.file)
	if fileExists(path) && !o.force {
		return fmt.Errorf("%s already exists (use `av edit`, or --force to overwrite)", path)
	}

	var plain []byte
	stdin := c.Stdin
	if o.from != "" {
		data, err := os.ReadFile(o.from)
		if err != nil {
			return err
		}
		if err := dotenv.Validate(data); err != nil {
			return fmt.Errorf("%s is not a valid .env file:\n%v", o.from, err)
		}
		plain = data
	} else {
		stdin = nil // reserved for the editor
	}

	t, err := o.newTarget(path, stdin)
	if err != nil {
		return err
	}

	if o.from == "" {
		content, changed, err := c.editor().Edit([]byte(newTemplate), dotenv.Validate)
		if err != nil {
			return err
		}
		if !changed {
			fmt.Fprintln(c.Stderr, "No changes made; nothing written.")
			return nil
		}
		plain = content
	}
	return c.save(path, plain, t)
}

func (c *CLI) editCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit an encrypted file in $EDITOR (re-encrypts on save)",
		Long: `Decrypt the file into a private temporary file, open $VISUAL/$EDITOR
(default vi) and re-encrypt it when you quit. Invalid content cannot be saved:
you will be asked to re-edit or abort. Nothing is written if nothing changed.
If the file is changed by someone else while you edit, you are asked before
overwriting it.

For vim and neovim, swap, backup, undo and viminfo files are turned off so
no plaintext copy is left behind.

-r, -R and -p replace how the file is encrypted (and update <file>.recipients).`,
		Args: noArgs,
		RunE: func(*cobra.Command, []string) error {
			path := EncPath(o.file)
			resolve := func(info crypt.Info) (target, bool, error) {
				// Stdin is reserved for the editor.
				if t, ok, err := o.explicitTarget(nil); ok || err != nil {
					return t, true, err
				}
				t, err := sameTarget(path, info)
				return t, false, err
			}
			return c.update(&o, path, resolve, func(plain []byte) ([]byte, bool, error) {
				return c.editor().Edit(plain, dotenv.Validate)
			})
		},
	}
	fs := cmd.Flags()
	addFileFlag(fs, &o)
	addIdentityFlag(fs, &o)
	addRecipientFlags(fs, &o, "re-encrypt")
	registerCompletions(cmd)
	return cmd
}

func (c *CLI) setCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "set KEY=VALUE... [KEY]",
		Short: "Set variables without opening an editor",
		Long: `Set variables, replacing existing lines in place and appending new ones.

Values given as KEY=VALUE end up in your shell history. For secrets, give
just KEY: the value is read without echo from the terminal, or from stdin
when it is not a terminal (e.g. "pbpaste | av set API_KEY").`,
		Args: minArgs(1, "KEY=VALUE or KEY"),
		RunE: func(_ *cobra.Command, args []string) error { return c.runSet(&o, args) },
	}
	addFileFlag(cmd.Flags(), &o)
	addIdentityFlag(cmd.Flags(), &o)
	registerCompletions(cmd)
	return cmd
}

func (c *CLI) runSet(o *options, args []string) error {
	type kv struct{ key, value string }
	var pairs []kv
	fromStdin := false
	for _, a := range args {
		key, value, ok := strings.Cut(a, "=")
		if !ok {
			if fromStdin {
				return errors.New("only one KEY can be read from stdin")
			}
			fromStdin = true
			v, err := c.readValue(key)
			if err != nil {
				return err
			}
			value = v
		}
		pairs = append(pairs, kv{key, value})
	}
	path := EncPath(o.file)
	return c.update(o, path, keepTarget(path, false), func(plain []byte) ([]byte, bool, error) {
		content := string(plain)
		for _, p := range pairs {
			var err error
			if content, err = dotenv.Set(content, p.key, p.value); err != nil {
				return nil, false, fmt.Errorf("%s: %v", path, err)
			}
		}
		return []byte(content), content != string(plain), nil
	})
}

// readValue reads the value for key without echo from a terminal, or as the
// whole of stdin (minus one trailing newline) otherwise.
func (c *CLI) readValue(key string) (string, error) {
	if f, ok := c.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		v, err := tty.ReadSecret(fmt.Sprintf("Value for %s:", key))
		return string(v), err
	}
	b, err := io.ReadAll(c.input())
	if err != nil {
		return "", err
	}
	s := strings.TrimSuffix(string(b), "\n")
	return strings.TrimSuffix(s, "\r"), nil
}

func (c *CLI) unsetCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "unset KEY...",
		Short: "Remove variables",
		Long:  "Remove variables. Fails, writing nothing, if any KEY is not set.",
		Args:  minArgs(1, "at least one KEY"),
		RunE: func(_ *cobra.Command, keys []string) error {
			path := EncPath(o.file)
			return c.update(&o, path, keepTarget(path, false), func(plain []byte) ([]byte, bool, error) {
				content, missing, err := dotenv.Unset(string(plain), keys...)
				if err != nil {
					return nil, false, fmt.Errorf("%s: %v", path, err)
				}
				if len(missing) > 0 {
					return nil, false, fmt.Errorf("not set in %s: %s", path, strings.Join(missing, ", "))
				}
				return []byte(content), true, nil
			})
		},
	}
	addFileFlag(cmd.Flags(), &o)
	addIdentityFlag(cmd.Flags(), &o)
	registerCompletions(cmd)
	return cmd
}
