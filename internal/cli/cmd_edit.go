package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/oneryx/av/internal/dotenv"
	"github.com/oneryx/av/internal/editor"
	"github.com/oneryx/av/internal/tty"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Commands that encrypt a file or change its content.

// editor returns an editor for the content of path. Env files are edited as
// ".env" and text files under their own name, so editors pick the right mode.
func (c *CLI) editor(path string) *editor.Editor {
	name := ".env"
	if !isEnvPath(path) {
		name = filepath.Base(path)
	}
	return &editor.Editor{Command: c.Editor, Name: name, In: c.input(), Out: c.Stderr}
}

// validatorFor returns the check for content saved to path: KEY=VALUE lines
// for env files, anything for text files.
func validatorFor(path string) func([]byte) error {
	if isEnvPath(path) {
		return dotenv.Validate
	}
	return func([]byte) error { return nil }
}

func (c *CLI) encryptCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "encrypt FILE",
		Short: "Encrypt FILE to FILE.age (FILE is left untouched)",
		Long: `Encrypt FILE to FILE.age next to it. FILE.age is refused if it exists unless
--force is given. If the result is a .env.age file (e.g. .env or prod.env),
FILE must be valid KEY=VALUE lines.

Recipients are chosen from -r/-R, then recipients.txt if it exists, then
the public key of your identity.`,
		Example: "  av encrypt secrets.pem          # secrets.pem.age\n  av encrypt .env                 # .env.age\n  av encrypt -R team.txt app.json",
		Args:    exactArgs(1, "exactly one FILE"),
		RunE:    func(_ *cobra.Command, args []string) error { return c.runEncrypt(&o, args[0]) },
	}
	fs := cmd.Flags()
	fs.BoolVar(&o.force, "force", false, "overwrite an existing FILE.age")
	addRecipientFlags(fs, &o, "encrypt")
	addIdentityFlag(fs, &o)
	fs.Lookup("identity").Usage = "identity `PATH` whose public key is used when no recipients are given (repeatable)"
	return cmd
}

func (c *CLI) runEncrypt(o *options, input string) error {
	out := input + ".age"
	if fileExists(out) && !o.force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", out)
	}
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	if err := validatorFor(out)(data); err != nil {
		return fmt.Errorf("%s is not a valid .env file:\n%v", input, err)
	}
	t, err := o.newTarget(c.Stdin)
	if err != nil {
		return err
	}
	return c.save(out, data, t)
}

func (c *CLI) editCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "edit [FILE]",
		Short: "Edit an encrypted file in $EDITOR (re-encrypts on save)",
		Long: `Decrypt the file into a private temporary file, open $VISUAL/$EDITOR
(default vi) and re-encrypt it when you quit. Invalid content cannot be saved:
you will be asked to re-edit or abort. Nothing is written if nothing changed.
If the file is changed by someone else while you edit, you are asked before
overwriting it.

For vim and neovim, swap, backup, undo and viminfo files are turned off so
no plaintext copy is left behind.

-r and -R replace how the file is encrypted for this save only; use
"av recipients edit" to change the recipients file.`,
		Args:              withFile(true, noArgs),
		ValidArgsFunction: completeFile,
		RunE: func(_ *cobra.Command, args []string) error {
			o.takeFile(args, true)
			path := EncPath(o.file)
			resolve := func() (target, bool, error) {
				// Stdin is reserved for the editor.
				if t, ok, err := o.explicitTarget(nil); ok || err != nil {
					return t, true, err
				}
				// Saving re-encrypts even if the content is unchanged, so an
				// edit picks up the current recipients.
				t, err := o.newTarget(nil)
				return t, true, err
			}
			return c.update(&o, path, resolve, func(plain []byte) ([]byte, bool, error) {
				return c.editor(path).Edit(plain, validatorFor(path))
			})
		},
	}
	fs := cmd.Flags()
	addIdentityFlag(fs, &o)
	addRecipientFlags(fs, &o, "re-encrypt")
	return cmd
}

func (c *CLI) setCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "set KEY=VALUE... [FILE.age]",
		Short: "Set variables without opening an editor",
		Long: `Set variables, replacing existing lines in place and appending new ones.

Values given as KEY=VALUE end up in your shell history. For secrets, give
just KEY: the value is read without echo from the terminal, or from stdin
when it is not a terminal (e.g. "pbpaste | av set API_KEY").

The file is the last argument if it ends in ".age" (keys never contain dots).`,
		Args: withFile(false, minArgs(1, "KEY=VALUE or KEY")),
		RunE: func(_ *cobra.Command, args []string) error {
			return c.runSet(&o, o.takeFile(args, false))
		},
	}
	addIdentityFlag(cmd.Flags(), &o)
	return cmd
}

func (c *CLI) runSet(o *options, args []string) error {
	path := EncPath(o.file)
	if err := requireEnv(path, "set"); err != nil {
		return err
	}
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
	return c.update(o, path, keepTarget(o), func(plain []byte) ([]byte, bool, error) {
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
		Use:   "unset KEY... [FILE.age]",
		Short: "Remove variables",
		Long:  "Remove variables. Fails, writing nothing, if any KEY is not set.\n\nThe file is the last argument if it ends in \".age\".",
		Args:  withFile(false, minArgs(1, "at least one KEY")),
		RunE: func(_ *cobra.Command, args []string) error {
			keys := o.takeFile(args, false)
			path := EncPath(o.file)
			if err := requireEnv(path, "unset"); err != nil {
				return err
			}
			return c.update(&o, path, keepTarget(&o), func(plain []byte) ([]byte, bool, error) {
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
	addIdentityFlag(cmd.Flags(), &o)
	return cmd
}
