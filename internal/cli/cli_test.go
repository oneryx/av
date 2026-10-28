package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

type env struct {
	t        *testing.T
	dir      string
	key      *age.X25519Identity
	keyFile  string
	contents string // directory of contentN files fed to the fake editor
}

// setup creates a working directory, an identity in AV_IDENTITY and a fake
// editor that copies content1, content2, ... into the file on each run.
func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	key, keyFile := newKey(t, dir, "key.txt")

	contents := filepath.Join(dir, "editor")
	must(t, os.Mkdir(contents, 0o700))
	script := filepath.Join(contents, "fake-editor.sh")
	must(t, os.WriteFile(script, []byte(`#!/bin/sh
d=$(dirname "$0")
n=$(cat "$d/count" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$d/count"
[ ! -f "$d/hook$n" ] || sh "$d/hook$n"
[ ! -f "$d/content$n" ] || cp "$d/content$n" "$1"
`), 0o755))

	t.Chdir(dir)
	t.Setenv("AV_IDENTITY", keyFile)
	t.Setenv("AV_IDENTITY_DATA", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", script)
	return &env{t: t, dir: dir, key: key, keyFile: keyFile, contents: contents}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newKey(t *testing.T, dir, name string) (*age.X25519Identity, string) {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	must(t, err)
	file := filepath.Join(dir, name)
	must(t, os.WriteFile(file, []byte(key.String()+"\n"), 0o600))
	return key, file
}

func (e *env) write(name, content string) {
	e.t.Helper()
	must(e.t, os.WriteFile(name, []byte(content), 0o600))
}

// editorWrites queues content for successive editor runs.
func (e *env) editorWrites(contents ...string) {
	e.t.Helper()
	content, _ := filepath.Glob(filepath.Join(e.contents, "content*"))
	hooks, _ := filepath.Glob(filepath.Join(e.contents, "hook*"))
	for _, f := range append(append(content, hooks...), filepath.Join(e.contents, "count")) {
		os.Remove(f)
	}
	for i, c := range contents {
		must(e.t, os.WriteFile(filepath.Join(e.contents, fmt.Sprintf("content%d", i+1)), []byte(c), 0o600))
	}
}

// editorRunsHook runs a shell command at the start of editor run n.
func (e *env) editorRunsHook(n int, cmd string) {
	e.t.Helper()
	must(e.t, os.WriteFile(filepath.Join(e.contents, fmt.Sprintf("hook%d", n)), []byte(cmd), 0o600))
}

func (e *env) editorRuns() int {
	b, _ := os.ReadFile(filepath.Join(e.contents, "count"))
	var n int
	fmt.Sscan(string(b), &n)
	return n
}

func (e *env) run(stdin string, args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	c := &CLI{Version: "test", Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb}
	code = c.Run(args)
	return code, out.String(), errb.String()
}

func (e *env) mustRun(args ...string) string {
	e.t.Helper()
	code, out, errs := e.run("", args...)
	if code != 0 {
		e.t.Fatalf("av %v: exit %d: %s", args, code, errs)
	}
	return out
}

func TestEncPath(t *testing.T) {
	for in, want := range map[string]string{
		"":                ".env.age",
		".env":            ".env.age",
		".env.age":        ".env.age",
		"prod":            "prod.env.age",
		"prod.env":        "prod.env.age",
		"secrets.age":     "secrets.env.age",
		"dir/.env":        "dir/.env.age",
		"dir/app.env.age": "dir/app.env.age",
	} {
		if got := EncPath(in); got != want {
			t.Errorf("EncPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewFromAndPrintExport(t *testing.T) {
	e := setup(t)
	e.write(".env", "KEY1=VALUE1\nKEY2='it''s'\n")
	if code, _, errs := e.run("", "new", "--from", ".env"); code == 0 {
		t.Fatal("invalid --from file accepted")
	} else if !strings.Contains(errs, "line 2") {
		t.Fatalf("stderr = %q", errs)
	}

	e.write(".env", "# c\nKEY1=VALUE1\nKEY2=\"it's\"\n")
	e.mustRun("new", "--from", ".env")
	if _, err := os.Stat(".env"); err != nil {
		t.Fatal("--from file removed")
	}
	// Recipient derived from the identity is recorded in the sidecar.
	side, _ := os.ReadFile(".env.age.recipients")
	if !strings.Contains(string(side), e.key.Recipient().String()) {
		t.Fatalf("sidecar = %q", side)
	}
	if got := e.mustRun("print"); got != "# c\nKEY1=VALUE1\nKEY2=\"it's\"\n" {
		t.Fatalf("print = %q", got)
	}
	if got := e.mustRun("export"); got != "export KEY1='VALUE1'\nexport KEY2='it'\\''s'\n" {
		t.Fatalf("export = %q", got)
	}

	if code, _, _ := e.run("", "new", "--from", ".env"); code == 0 {
		t.Fatal("overwrote without --force")
	}
	e.mustRun("new", "--from", ".env", "--force")
}

func TestInteropWithAgeCLI(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age not installed")
	}
	e := setup(t)
	e.write("plain", "A=1\n")
	e.mustRun("new", "--from", "plain")
	out, err := exec.Command("age", "-d", "-i", e.keyFile, ".env.age").Output()
	if err != nil || string(out) != "A=1\n" {
		t.Fatalf("age -d: %q %v", out, err)
	}
}

func TestMultipleRecipientsAndSidecarReuse(t *testing.T) {
	e := setup(t)
	other, otherKey := newKey(t, e.dir, "other.txt")
	recFile := filepath.Join(e.dir, "team.txt")
	e.write(recFile, "# team\n"+other.Recipient().String()+"\n")

	e.write("plain", "A=1\n")
	e.mustRun("new", "-f", "prod", "--from", "plain", "-r", e.key.Recipient().String(), "-R", recFile)
	if got := e.mustRun("print", "-f", "prod", "-i", otherKey); got != "A=1\n" {
		t.Fatalf("other recipient print = %q", got)
	}

	// edit reuses the sidecar: both identities can still decrypt.
	e.editorWrites("A=2\n")
	e.mustRun("edit", "-f", "prod.env.age")
	for _, k := range []string{e.keyFile, otherKey} {
		if got := e.mustRun("print", "-f", "prod", "-i", k); got != "A=2\n" {
			t.Fatalf("print with %s = %q", k, got)
		}
	}

	// -r on edit replaces the recipients and rewrites the sidecar.
	e.editorWrites()
	e.mustRun("edit", "-f", "prod", "-r", e.key.Recipient().String())
	if code, _, _ := e.run("", "print", "-f", "prod", "-i", otherKey); code == 0 {
		t.Fatal("removed recipient can still decrypt")
	}
	side, _ := os.ReadFile("prod.env.age.recipients")
	if strings.Contains(string(side), other.Recipient().String()) {
		t.Fatalf("sidecar not updated: %q", side)
	}
}

func TestEditValidationLoop(t *testing.T) {
	e := setup(t)
	e.write("plain", "A=1\n")
	e.mustRun("new", "--from", "plain")
	before, _ := os.ReadFile(".env.age")

	// Invalid content, then abort: nothing is written.
	e.editorWrites("NOT VALID\n")
	code, _, errs := e.run("a\n", "edit")
	if code == 0 || !strings.Contains(errs, "not valid") || !strings.Contains(errs, "aborted") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	if after, _ := os.ReadFile(".env.age"); !bytes.Equal(before, after) {
		t.Fatal("file changed after abort")
	}

	// Invalid content, re-edit, then valid content: saved.
	e.editorWrites("NOT VALID\n", "A=1\nB=2\n")
	if code, _, errs := e.run("r\n", "edit"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if e.editorRuns() != 2 {
		t.Fatalf("editor ran %d times", e.editorRuns())
	}
	if got := e.mustRun("print"); got != "A=1\nB=2\n" {
		t.Fatalf("print = %q", got)
	}

	// No change: nothing written.
	before, _ = os.ReadFile(".env.age")
	e.editorWrites()
	_, _, errs = e.run("", "edit")
	if after, _ := os.ReadFile(".env.age"); !bytes.Equal(before, after) || !strings.Contains(errs, "No changes") {
		t.Fatalf("unchanged edit rewrote file: %s", errs)
	}
}

func TestNewWithEditor(t *testing.T) {
	e := setup(t)
	e.editorWrites() // template left unchanged
	_, _, errs := e.run("", "new")
	if _, err := os.Stat(".env.age"); err == nil || !strings.Contains(errs, "nothing written") {
		t.Fatalf("unchanged template created a file: %s", errs)
	}
	e.editorWrites("X=1\n")
	e.mustRun("new")
	if got := e.mustRun("print"); got != "X=1\n" {
		t.Fatalf("print = %q", got)
	}
}

func TestEditWithoutSidecar(t *testing.T) {
	e := setup(t)
	e.write("plain", "A=1\n")
	e.mustRun("new", "--from", "plain")
	os.Remove(".env.age.recipients")
	if code, _, errs := e.run("", "edit"); code == 0 || !strings.Contains(errs, "pass -r or -R") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func TestHelpAndVersion(t *testing.T) {
	e := setup(t)
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		if out := e.mustRun(args...); out != "av test\n" {
			t.Fatalf("%v = %q", args, out)
		}
	}
	help := e.mustRun("help")
	if !strings.Contains(help, `eval "$(av export)"`) {
		t.Fatal("help missing export usage")
	}
	for _, name := range []string{"new", "edit", "set", "unset", "print", "get", "export", "run", "recipients", "rekey", "completion"} {
		if !strings.Contains(help, "\n  "+name+" ") {
			t.Errorf("%s missing from help", name)
		}
	}
	if out := e.mustRun("help", "edit"); !strings.Contains(out, "av edit [flags]") {
		t.Fatalf("help edit = %q", out)
	}
	if out := e.mustRun("edit", "--help"); !strings.Contains(out, "--recipients-file") {
		t.Fatalf("edit --help = %q", out)
	}
	if out := e.mustRun("help", "recipients", "rm"); !strings.Contains(out, "SSH comment") {
		t.Fatalf("help recipients rm = %q", out)
	}
	for _, args := range [][]string{{}, {"bogus"}, {"print", "-z"}, {"help", "bogus"}, {"print", "extra"}, {"get"}, {"recipients", "bogus"}} {
		if code, _, errs := e.run("", args...); code != 2 {
			t.Errorf("av %v: exit %d, want 2: %s", args, code, errs)
		}
	}
}

// Flags may follow positional arguments, except for run's COMMAND.
func TestFlagsAfterArgs(t *testing.T) {
	e := setup(t)
	e.write("plain", "A=1\n")
	e.mustRun("new", "--from", "plain", "-f", "prod")
	e.mustRun("set", "B=2", "-f", "prod")
	if got := e.mustRun("get", "B", "-f", "prod"); got != "2\n" {
		t.Fatalf("get = %q", got)
	}
	if got := e.mustRun("run", "-f", "prod", "sh", "-c", `echo "$B"`, "-f"); got != "2\n" {
		t.Fatalf("run = %q", got)
	}
}

func TestCompletion(t *testing.T) {
	e := setup(t)
	e.write("plain", "A=1\n")
	e.mustRun("new", "--from", "plain", "-r", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA9AKW/hv45o73KQHNxvYSVkLfD922xtm9VpgrNCo2s7 alice", "-r", e.key.Recipient().String())
	out := e.mustRun("__complete", "recipients", "rm", "")
	if !strings.Contains(out, "alice\n") || !strings.Contains(out, e.key.Recipient().String()) {
		t.Fatalf("completion = %q", out)
	}
	if out := e.mustRun("__complete", "print", "-f", ""); !strings.Contains(out, "age") {
		t.Fatalf("-f completion = %q", out)
	}
	if out := e.mustRun("completion", "zsh"); !strings.Contains(out, "#compdef av") {
		t.Fatal("no zsh completion script")
	}
}

func TestSaveListsRecipients(t *testing.T) {
	e := setup(t)
	e.write("plain", "A=1\n")
	_, _, errs := e.run("", "new", "--from", "plain")
	if !strings.Contains(errs, "encrypted to:\n    "+e.key.Recipient().String()) {
		t.Fatalf("stderr = %q", errs)
	}
}

func TestConcurrentChangeDetected(t *testing.T) {
	e := setup(t)
	e.write("plain", "A=1\n")
	e.mustRun("new", "--from", "plain")

	// Someone else rewrites the file while the editor is open; answer "no".
	e.editorWrites("A=2\n")
	e.editorRunsHook(1, "echo theirs > "+filepath.Join(e.dir, ".env.age"))
	code, _, errs := e.run("n\n", "edit")
	if code == 0 || !strings.Contains(errs, "changed by someone else") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if b, _ := os.ReadFile(".env.age"); string(b) != "theirs\n" {
		t.Fatalf("their change was overwritten: %q", b)
	}

	// Answer "yes": ours wins.
	e.mustRun("new", "--from", "plain", "--force")
	e.editorWrites("A=2\n")
	e.editorRunsHook(1, "echo theirs >> "+filepath.Join(e.dir, ".env.age"))
	if code, _, errs := e.run("y\n", "edit"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if got := e.mustRun("print"); got != "A=2\n" {
		t.Fatalf("print = %q", got)
	}
}

func TestPassphraseSaveRemovesSidecar(t *testing.T) {
	e := setup(t)
	e.write("plain", "A=1\n")
	e.mustRun("new", "--from", "plain")
	tg, err := passphraseTarget("pw")
	must(t, err)
	c := &CLI{Stderr: new(bytes.Buffer)}
	must(t, c.save(".env.age", []byte("A=1\n"), tg))
	if _, err := os.Stat(".env.age.recipients"); err == nil {
		t.Fatal("stale recipients file kept for a passphrase file")
	}
}

func TestGetSetUnset(t *testing.T) {
	e := setup(t)
	e.write("plain", "# keep me\nA=1\nexport B=2\n")
	e.mustRun("new", "--from", "plain")

	if got := e.mustRun("get", "B"); got != "2\n" {
		t.Fatalf("get = %q", got)
	}
	if code, _, _ := e.run("", "get", "NOPE"); code != 1 {
		t.Fatal("get of missing key should fail")
	}
	e.mustRun("set", "A=one two", "C=3")
	if code, _, errs := e.run("multi\nline\n", "set", "SECRET"); code != 0 {
		t.Fatalf("set from stdin: %s", errs)
	}
	if got := e.mustRun("get", "SECRET"); got != "multi\nline\n" {
		t.Fatalf("SECRET = %q", got)
	}
	if code, _, _ := e.run("", "unset", "B", "NOPE"); code == 0 {
		t.Fatal("unset of missing key should fail")
	}
	e.mustRun("unset", "B")
	want := "# keep me\nA=\"one two\"\nC=3\nSECRET=\"multi\\nline\"\n"
	if got := e.mustRun("print"); got != want {
		t.Fatalf("print = %q, want %q", got, want)
	}
	if code, _, _ := e.run("", "set", "1BAD=x"); code == 0 {
		t.Fatal("invalid key accepted")
	}
}

func TestRun(t *testing.T) {
	e := setup(t)
	e.write("plain", "A=\"it's\"\nHOME=/override\n")
	e.mustRun("new", "--from", "plain")
	if got := e.mustRun("run", "--", "sh", "-c", `printf '%s|%s' "$A" "$HOME"`); got != "it's|/override" {
		t.Fatalf("run = %q", got)
	}
	if code, _, _ := e.run("", "run", "sh", "-c", "exit 7"); code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	if code, _, _ := e.run("", "run"); code != 2 {
		t.Fatal("run without command should exit 2")
	}
}

func TestRecipientsAddRmRekey(t *testing.T) {
	e := setup(t)
	other, otherKey := newKey(t, e.dir, "other.txt")
	e.write("plain", "A=1\n")
	e.mustRun("new", "--from", "plain")

	e.mustRun("recipients", "add", other.Recipient().String())
	if got := e.mustRun("print", "-i", otherKey); got != "A=1\n" {
		t.Fatalf("added recipient can't decrypt: %q", got)
	}
	if got := e.mustRun("recipients"); got != e.key.Recipient().String()+"\n"+other.Recipient().String()+"\n" {
		t.Fatalf("list = %q", got)
	}
	if code, _, _ := e.run("", "recipients", "rm", "age1nope"); code == 0 {
		t.Fatal("removing an unknown recipient succeeded")
	}
	e.mustRun("recipients", "rm", other.Recipient().String())
	if code, _, _ := e.run("", "print", "-i", otherKey); code == 0 {
		t.Fatal("removed recipient can still decrypt")
	}
	if code, _, _ := e.run("", "recipients", "rm", e.key.Recipient().String()); code == 0 {
		t.Fatal("removed the last recipient")
	}

	// rekey picks up a recipients file changed by hand (e.g. by a git pull).
	e.write(".env.age.recipients", other.Recipient().String()+"\n")
	e.mustRun("rekey")
	if got := e.mustRun("print", "-i", otherKey); got != "A=1\n" {
		t.Fatalf("after rekey: %q", got)
	}
}

func TestMatchRecipient(t *testing.T) {
	line := "ssh-ed25519 AAAAkey alice@laptop"
	for arg, want := range map[string]bool{
		line:                    true,
		"ssh-ed25519 AAAAkey":   true,
		"alice@laptop":          true,
		"ssh-ed25519 AAAAother": false,
		"alice":                 false,
	} {
		if matchRecipient(line, arg) != want {
			t.Errorf("matchRecipient(%q) = %v", arg, !want)
		}
	}
}

func TestIdentityEnv(t *testing.T) {
	e := setup(t)
	e.write("plain", "A=1\n")
	other, otherKey := newKey(t, e.dir, "other.txt")
	e.mustRun("new", "--from", "plain", "-r", other.Recipient().String())

	// AV_IDENTITY takes a list of files.
	t.Setenv("AV_IDENTITY", e.keyFile+string(os.PathListSeparator)+otherKey)
	e.mustRun("print")

	// AV_IDENTITY_DATA holds the key itself.
	t.Setenv("AV_IDENTITY", "")
	t.Setenv("HOME", e.dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AV_IDENTITY_DATA", other.String())
	e.mustRun("print")

	t.Setenv("AV_IDENTITY_DATA", "")
	if _, _, errs := e.run("", "print"); !strings.Contains(errs, "AV_IDENTITY_DATA") {
		t.Fatalf("no-identity hint missing: %s", errs)
	}
	t.Setenv("AV_IDENTITY", "/nonexistent/key")
	if code, _, _ := e.run("", "print"); code == 0 {
		t.Fatal("missing $AV_IDENTITY file should be an error")
	}
}
