package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/oneryx/av/internal/dotenv"
	"github.com/spf13/cobra"
)

// Commands that read a file without changing it.

// readCmd builds a command with just -f and -i.
func readCmd(o *options, cmd *cobra.Command) *cobra.Command {
	addFileFlag(cmd.Flags(), o)
	addIdentityFlag(cmd.Flags(), o)
	registerCompletions(cmd)
	return cmd
}

func (c *CLI) printCmd() *cobra.Command {
	var o options
	return readCmd(&o, &cobra.Command{
		Use:   "print",
		Short: "Print the decrypted content",
		Args:  noArgs,
		RunE: func(*cobra.Command, []string) error {
			plain, _, _, err := o.decrypt(EncPath(o.file))
			if err != nil {
				return err
			}
			_, err = c.Stdout.Write(plain)
			return err
		},
	})
}

func (c *CLI) getCmd() *cobra.Command {
	var o options
	return readCmd(&o, &cobra.Command{
		Use:   "get KEY",
		Short: "Print the value of one variable",
		Long:  "Print the value of KEY. Fails if KEY is not set.",
		Args:  exactArgs(1, "exactly one KEY"),
		RunE: func(_ *cobra.Command, args []string) error {
			entries, err := o.entries()
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
		Use:   "export",
		Short: "Print shell export statements (use with eval)",
		Long: `Print "export KEY='VALUE'" lines for every variable. A program cannot change
its parent shell's environment, so evaluate the output:

    eval "$(av export)"

or install the shell function shown in "av help". Prefer "av run" when you
only need the variables for one command.`,
		Args: noArgs,
		RunE: func(*cobra.Command, []string) error {
			entries, err := o.entries()
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
		Use:   "run [flags] [--] COMMAND [ARGS...]",
		Short: "Run a command with the variables in its environment",
		Long: `Run COMMAND with the variables added to its environment, without exporting
them into your shell. Variables in the file override inherited ones. av exits
with COMMAND's exit status.

av's own flags must come before COMMAND; everything after it is passed on.`,
		Example: "  av run -- npm start\n  av run -f prod ./deploy.sh --dry-run",
		Args:    minArgs(1, "a COMMAND to run"),
		RunE: func(_ *cobra.Command, argv []string) error {
			entries, err := o.entries()
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
