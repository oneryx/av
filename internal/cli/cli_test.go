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
	editor   string // the fake editor command
}

// setup creates a working directory with HOME set to it, an identity at the
// default location ~/.config/age/keys.txt, and a fake editor that copies
// content1, content2, ... into the file on each run.
func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".config", "age")
	must(t, os.MkdirAll(cfg, 0o700))
	key, keyFile := newKey(t, cfg, "keys.txt")

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
	// HOME isolates the default identity and recipients locations.
	t.Setenv("HOME", dir)
	return &env{t: t, dir: dir, key: key, keyFile: keyFile, contents: contents, editor: script}
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
	c := &CLI{Version: "test", Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb, Editor: e.editor}
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
		"secrets.age":     "secrets.age",
		"notes.txt":       "notes.txt.env.age",
		"dir/.env":        "dir/.env.age",
		"dir/app.env.age": "dir/app.env.age",
	} {
		if got := EncPath(in); got != want {
			t.Errorf("EncPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Env files are validated and get the KEY=VALUE commands; text files are not.
func TestEncrypt(t *testing.T) {
	e := setup(t)

	// Env file: invalid content is refused, valid content round-trips.
	e.write(".env", "KEY1=VALUE1\nKEY2='it''s'\n")
	if code, _, errs := e.run("", "encrypt", ".env"); code == 0 || !strings.Contains(errs, "line 2") {
		t.Fatalf("invalid env file: exit %d, stderr %q", code, errs)
	}
	e.write(".env", "# c\nKEY1=VALUE1\nKEY2=\"it's\"\n")
	if code, _, errs := e.run("", "encrypt", ".env"); code != 0 || !strings.Contains(errs, "encrypted to:\n    "+e.key.Recipient().String()) {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	if got := e.mustRun("get"); got != "# c\nKEY1=VALUE1\nKEY2=\"it's\"\n" {
		t.Fatalf("get = %q", got)
	}
	if got := e.mustRun("export"); got != "export KEY1='VALUE1'\nexport KEY2='it'\\''s'\n" {
		t.Fatalf("export = %q", got)
	}
	if _, err := os.Stat(".env"); err != nil {
		t.Fatal("input removed")
	}
	if code, _, _ := e.run("", "encrypt", ".env"); code == 0 {
		t.Fatal("overwrote without --force")
	}
	e.mustRun("encrypt", "--force", ".env")

	// Text file: any content, saved as is.
	text := "-----BEGIN KEY-----\nnot KEY=VALUE at all\n"
	e.write("secrets.pem", text)
	e.mustRun("encrypt", "secrets.pem")
	if got := e.mustRun("get", "secrets.pem.age"); got != text {
		t.Fatalf("get = %q", got)
	}
}

// Text files: edits skip validation, and env-only commands refuse them.
func TestTextFiles(t *testing.T) {
	e := setup(t)
	e.write("secrets.txt", "plain\n")
	e.mustRun("encrypt", "secrets.txt")

	e.editorWrites("just some text\n")
	e.mustRun("edit", "secrets.txt.age")
	if got := e.mustRun("get", "secrets.txt.age"); got != "just some text\n" {
		t.Fatalf("get after edit = %q", got)
	}

	for _, args := range [][]string{
		{"get", "X", "secrets.txt.age"}, {"set", "X=1", "secrets.txt.age"}, {"unset", "X", "secrets.txt.age"},
		{"export", "secrets.txt.age"}, {"run", "secrets.txt.age", "--", "true"},
	} {
		code, _, errs := e.run("", args...)
		if code == 0 || !strings.Contains(errs, "text file") {
			t.Fatalf("av %v on text file: exit %d, stderr %q", args, code, errs)
		}
	}
}

func TestInteropWithAgeCLI(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age not installed")
	}
	e := setup(t)
	e.write(".env", "A=1\n")
	e.mustRun("encrypt", ".env")
	out, err := exec.Command("age", "-d", "-i", e.keyFile, ".env.age").Output()
	if err != nil || string(out) != "A=1\n" {
		t.Fatalf("age -d: %q %v", out, err)
	}
}

// Recipients: the file is used when present, get/edit manage it, edit
// validates it, and ./recipients.txt wins over the config directory's copy.
func TestRecipients(t *testing.T) {
	e := setup(t)
	other, otherKey := newKey(t, e.dir, "other.txt")

	// Without recipients.txt, files go to the own key and no file is written.
	e.write(".env", "A=1\n")
	e.mustRun("encrypt", ".env")
	for _, f := range []string{recipientsFileName, ".env.age.recipients"} {
		if _, err := os.Stat(f); err == nil {
			t.Fatalf("%s was written", f)
		}
	}

	// The config directory's file is used when there is no ./recipients.txt.
	cfg, err := configRecipientsPath()
	must(t, err)
	must(t, os.MkdirAll(filepath.Dir(cfg), 0o700))
	e.write(cfg, other.Recipient().String()+"\n")
	e.mustRun("encrypt", "--force", ".env")
	if got := e.mustRun("get", "-i", otherKey); got != "A=1\n" {
		t.Fatalf("config recipients not used: %q", got)
	}
	if got := e.mustRun("recipients", "get"); got != other.Recipient().String()+"\n" {
		t.Fatalf("get = %q", got)
	}

	// ./recipients.txt wins.
	e.write(recipientsFileName, e.key.Recipient().String()+"\n")
	e.mustRun("encrypt", "--force", ".env")
	if code, _, _ := e.run("", "get", "-i", otherKey); code == 0 {
		t.Fatal("config file used although ./recipients.txt exists")
	}
	if got := e.mustRun("get"); got != "A=1\n" {
		t.Fatalf("get = %q", got)
	}

	// recipients edit changes the file but does not re-encrypt; saving the
	// file with edit does, even without changes.
	e.editorWrites(e.key.Recipient().String() + "\n" + other.Recipient().String() + "\n")
	e.mustRun("recipients", "edit")
	if code, _, _ := e.run("", "get", "-i", otherKey); code == 0 {
		t.Fatal("recipients edit re-encrypted the file")
	}
	e.editorWrites()
	e.mustRun("edit")
	if got := e.mustRun("get", "-i", otherKey); got != "A=1\n" {
		t.Fatalf("after edit: %q", got)
	}

	// Invalid and empty recipient lists are rejected; the file is kept.
	before, _ := os.ReadFile(recipientsFileName)
	e.editorWrites("not a key\n")
	if code, _, errs := e.run("a\n", "recipients", "edit"); code == 0 || !strings.Contains(errs, "aborted") {
		t.Fatalf("invalid recipients: exit %d, stderr %q", code, errs)
	}
	e.editorWrites("# nothing\n")
	if code, _, errs := e.run("a\n", "recipients", "edit"); code == 0 || !strings.Contains(errs, "no recipients") {
		t.Fatalf("empty recipients: exit %d, stderr %q", code, errs)
	}
	if after, _ := os.ReadFile(recipientsFileName); !bytes.Equal(before, after) {
		t.Fatal("recipients file changed after abort")
	}
}

func TestEditValidationLoop(t *testing.T) {
	e := setup(t)
	e.write(".env", "A=1\n")
	e.mustRun("encrypt", ".env")
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
	if got := e.mustRun("get"); got != "A=1\nB=2\n" {
		t.Fatalf("get = %q", got)
	}

	// No change: the file is still saved (re-encrypted for the current recipients).
	e.editorWrites()
	_, _, errs = e.run("", "edit")
	if got := e.mustRun("get"); got != "A=1\nB=2\n" || !strings.Contains(errs, "Wrote") {
		t.Fatalf("unchanged edit: get %q, stderr %s", got, errs)
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
	for _, name := range []string{"encrypt", "edit", "set", "unset", "get", "export", "run", "recipients"} {
		if !strings.Contains(help, "\n  "+name+" ") {
			t.Errorf("%s missing from help", name)
		}
	}
	if code, _, _ := e.run("", "new"); code != 2 {
		t.Errorf("av new: exit %d, want 2 (command removed)", code)
	}
	for _, args := range [][]string{{"bogus"}, {"get", "-z"}, {"help", "bogus"}, {"get", "a", "b"}, {"recipients", "bogus", "x"}} {
		if code, _, errs := e.run("", args...); code != 2 {
			t.Errorf("av %v: exit %d, want 2: %s", args, code, errs)
		}
	}
}

func TestCompletion(t *testing.T) {
	e := setup(t)
	e.write(".env", "A=1\n")
	e.mustRun("encrypt", ".env")
	if out := e.mustRun("completion", "zsh"); !strings.Contains(out, "#compdef av") {
		t.Fatal("no zsh completion script")
	}
}

func TestConcurrentChangeDetected(t *testing.T) {
	e := setup(t)
	e.write(".env", "A=1\n")
	e.mustRun("encrypt", ".env")

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
	e.mustRun("encrypt", ".env", "--force")
	e.editorWrites("A=2\n")
	e.editorRunsHook(1, "echo theirs >> "+filepath.Join(e.dir, ".env.age"))
	if code, _, errs := e.run("y\n", "edit"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if got := e.mustRun("get"); got != "A=2\n" {
		t.Fatalf("get = %q", got)
	}
}

func TestGetSetUnset(t *testing.T) {
	e := setup(t)
	e.write(".env", "# keep me\nA=1\nexport B=2\n")
	e.mustRun("encrypt", ".env")

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
	if got := e.mustRun("get"); got != want {
		t.Fatalf("get = %q, want %q", got, want)
	}
	if code, _, _ := e.run("", "set", "1BAD=x"); code == 0 {
		t.Fatal("invalid key accepted")
	}
	// The file is the last argument, so a name without .age is a key.
	if code, _, _ := e.run("", "get", "A", "prod"); code == 0 {
		t.Fatal("get accepted a file name without .age")
	}
}

func TestRun(t *testing.T) {
	e := setup(t)
	e.write(".env", "A=\"it's\"\nHOME=/override\n")
	e.mustRun("encrypt", ".env")
	if got := e.mustRun("run", "--", "sh", "-c", `printf '%s|%s' "$A" "$HOME"`); got != "it's|/override" {
		t.Fatalf("run = %q", got)
	}
	if got := e.mustRun("run", ".env.age", "sh", "-c", `echo "$A"`); got != "it's\n" {
		t.Fatalf("run with file first = %q", got)
	}
	if code, _, _ := e.run("", "run", "sh", "-c", "exit 7"); code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	if code, _, _ := e.run("", "run"); code != 2 {
		t.Fatal("run without command should exit 2")
	}
}

func TestIdentityFlags(t *testing.T) {
	e := setup(t)
	e.write(".env", "A=1\n")
	other, otherKey := newKey(t, e.dir, "other.txt")
	e.mustRun("encrypt", ".env", "-r", other.Recipient().String())

	// -i may be repeated.
	if got := e.mustRun("get", "-i", e.keyFile, "-i", otherKey); got != "A=1\n" {
		t.Fatalf("get = %q", got)
	}
	// An explicit -i file that doesn't exist is an error.
	if code, _, _ := e.run("", "get", "-i", "/nonexistent/key"); code == 0 {
		t.Fatal("missing -i file should be an error")
	}
	// Without -i, the default location is used; without that, there's a hint.
	os.Remove(e.keyFile)
	if _, _, errs := e.run("", "get"); !strings.Contains(errs, "no identity found") {
		t.Fatalf("no-identity hint missing: %s", errs)
	}
	if got := e.mustRun("get", "-i", otherKey); got != "A=1\n" {
		t.Fatalf("get = %q", got)
	}
}
