package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/oneryx/av/internal/dotenv"
	"github.com/spf13/cobra"
)

// Commands that read a file without changing it.

// readCmd adds -i to a command that reads a file.
func readCmd(o *options, cmd *cobra.Command) *cobra.Command {
	addIdentityFlag(cmd.Flags(), o)
	return cmd
}

func (c *CLI) getCmd() *cobra.Command {
	var o options
	return readCmd(&o, &cobra.Command{
		Use:   "get [KEY] [FILE.age]",
		Short: "Print the decrypted content, or the value of one variable",
		Long: `Without KEY, print the decrypted content of the file. With KEY, print its
value; it fails if KEY is not set.

The file is the last argument if it ends in ".age" (keys never contain dots).`,
		Args: withFile(false, func(_ *cobra.Command, rest []string) error {
			if len(rest) > 1 {
				return usagef("expected at most one KEY")
			}
			return nil
		}),
		RunE: func(_ *cobra.Command, args []string) error {
			args = o.takeFile(args, false)
			if len(args) == 0 {
				plain, _, err := o.decrypt(EncPath(o.file))
				if err != nil {
					return err
				}
				_, err = c.Stdout.Write(plain)
				return err
			}
			entries, err := o.entries("get")
			if err != nil {
				return err
			}
			for _, e := range entries {
				if e.Key == args[0] {
					_, err := fmt.Fprintln(c.Stdout, e.Value)
					return err
				}
			}
			return fmt.Errorf("%s is not set", args[0])
		},
	})
}

func (c *CLI) exportCmd() *cobra.Command {
	var o options
	return readCmd(&o, &cobra.Command{
		Use:   "export [FILE]",
		Short: "Print shell export statements (use with eval)",
		Long: `Print "export KEY='VALUE'" lines for every variable. A program cannot change
its parent shell's environment, so evaluate the output:

    eval "$(av export)"

or install the shell function shown in "av help". Prefer "av run" when you
only need the variables for one command.`,
		Args:              withFile(true, noArgs),
		ValidArgsFunction: completeFile,
		RunE: func(_ *cobra.Command, args []string) error {
			o.takeFile(args, true)
			entries, err := o.entries("export")
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(c.Stdout, dotenv.ExportScript(entries))
			return err
		},
	})
}

func (c *CLI) runCmd() *cobra.Command {
	var o options
	cmd := readCmd(&o, &cobra.Command{
		Use:   "run [FILE.age] [--] COMMAND [ARGS...]",
		Short: "Run a command with the variables in its environment",
		Long: `Run COMMAND with the variables added to its environment, without exporting
them into your shell. Variables in the file override inherited ones. av exits
with COMMAND's exit status.

The file, if given, comes first and must end in ".age". av's own flags must
come before COMMAND; everything after it is passed on.`,
		Example: "  av run -- npm start\n  av run prod.env.age ./deploy.sh --dry-run",
		Args:    minArgs(1, "a COMMAND to run"),
		RunE: func(_ *cobra.Command, argv []string) error {
			if len(argv) > 1 && strings.HasSuffix(argv[0], ".age") {
				o.file, argv = argv[0], argv[1:]
				if argv[0] == "--" {
					argv = argv[1:]
				}
			}
			if len(argv) == 0 {
				return usagef("expected a COMMAND to run")
			}
			entries, err := o.entries("run")
			if err != nil {
				return err
			}
			return c.runWithEnv(entries, argv)
		},
	})
	// Leave flags after COMMAND to COMMAND.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func (c *CLI) runWithEnv(entries []dotenv.Entry, argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	// Later entries win over the inherited environment.
	cmd.Env = os.Environ()
	for _, e := range entries {
		cmd.Env = append(cmd.Env, e.Key+"="+e.Value)
	}

	// Ctrl+C reaches the child directly through the terminal; forward the
	// signals that don't, and stay alive until the child exits.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case s := <-sigs:
				if s != syscall.SIGINT {
					cmd.Process.Signal(s)
				}
			}
		}
	}()

	err := cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return exitCode(128 + int(ws.Signal()))
		}
		return exitCode(exitErr.ExitCode())
	}
	return err
}
