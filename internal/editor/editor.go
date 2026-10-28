// Package editor lets the user edit plaintext in an external editor via a
// private temporary file, re-opening the editor until the content is valid.
package editor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// ErrAborted is returned when the user chooses to abort editing.
var ErrAborted = errors.New("edit aborted, nothing saved")

// Editor runs an external editor on a temporary file.
type Editor struct {
	// Command is the editor command line, run via "sh -c". Defaults to
	// $VISUAL, $EDITOR, then vi.
	Command string
	// In and Out are used for the re-edit prompt. Default os.Stdin / os.Stderr.
	In  io.Reader
	Out io.Writer
	// Name is the base name for the temporary file, e.g. ".env".
	Name string
}

// DefaultCommand returns the user's preferred editor.
func DefaultCommand() string {
	for _, v := range []string{"VISUAL", "EDITOR"} {
		if e := strings.TrimSpace(os.Getenv(v)); e != "" {
			return e
		}
	}
	return "vi"
}

// Edit opens initial in the editor and returns the edited content once it
// passes validate. changed is false if the content was not modified.
func (e *Editor) Edit(initial []byte, validate func([]byte) error) (content []byte, changed bool, err error) {
	cmdline := e.Command
	if cmdline == "" {
		cmdline = DefaultCommand()
	}
	in, out := e.In, e.Out
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stderr
	}
	name := e.Name
	if name == "" {
		name = ".env"
	}

	dir, err := os.MkdirTemp(tempBase(), "av-")
	if err != nil {
		return nil, false, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	defer cleanup()

	// Make sure plaintext never outlives us. SIGINT is ignored while the
	// editor runs (the editor handles Ctrl+C itself) and aborts otherwise.
	var editing atomic.Bool
	sigs := make(chan os.Signal, 1)
	done := make(chan struct{})
	defer close(done)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	go func() {
		for {
			select {
			case <-done:
				return
			case s := <-sigs:
				if s == syscall.SIGINT && editing.Load() {
					continue
				}
				cleanup()
				fmt.Fprintln(out, "\nav: interrupted, nothing saved")
				os.Exit(130)
			}
		}
	}()

	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, initial, 0o600); err != nil {
		return nil, false, err
	}

	reader := bufio.NewReader(in)
	for {
		editing.Store(true)
		err := run(cmdline, file)
		editing.Store(false)
		if err != nil {
			return nil, false, fmt.Errorf("editor %q failed: %v", cmdline, err)
		}
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, false, err
		}
		if bytes.Equal(content, initial) {
			return content, false, nil
		}
		verr := validate(content)
		if verr == nil {
			return content, true, nil
		}
		fmt.Fprintf(out, "\nThe file is not valid and cannot be saved:\n%s\n\n", indent(verr.Error()))
		for {
			fmt.Fprint(out, "[r]e-edit or [a]bort? ")
			line, rerr := reader.ReadString('\n')
			answer := strings.ToLower(strings.TrimSpace(line))
			if answer == "a" || answer == "abort" || (rerr != nil && answer == "") {
				return nil, false, ErrAborted
			}
			if answer == "r" || answer == "re-edit" || answer == "" {
				break
			}
		}
	}
}

func run(cmdline, file string) error {
	cmdline = hardenVim(cmdline, isVim)
	cmd := exec.Command("sh", "-c", cmdline+` "$@"`, "sh", file)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// vimFlags stop vim and neovim from writing swap, backup, undo and
// viminfo/shada files, which would copy plaintext out of the temp directory.
const vimFlags = ` -n -i NONE --cmd 'set nobackup nowritebackup noswapfile noundofile'`

// hardenVim appends vimFlags when cmdline runs vim or neovim. "vi" is only
// treated as vim if isVim confirms it (it may be nvi or busybox vi).
func hardenVim(cmdline string, isVim func(string) bool) string {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return cmdline
	}
	switch filepath.Base(fields[0]) {
	case "vim", "nvim":
		return cmdline + vimFlags
	case "vi":
		if isVim(fields[0]) {
			return cmdline + vimFlags
		}
	}
	return cmdline
}

func isVim(prog string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, prog, "--version").Output()
	return bytes.HasPrefix(out, []byte("VIM")) || bytes.HasPrefix(out, []byte("NVIM"))
}

// tempBase prefers a memory-backed filesystem on Linux.
func tempBase() string {
	if runtime.GOOS == "linux" {
		if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
			return "/dev/shm"
		}
	}
	return os.TempDir()
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}
