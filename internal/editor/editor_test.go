package editor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHardenVim(t *testing.T) {
	yes := func(string) bool { return true }
	no := func(string) bool { return false }
	for _, c := range []struct {
		cmd   string
		isVim func(string) bool
		want  bool
	}{
		{"vim", no, true},
		{"/usr/bin/nvim -u NONE", no, true},
		{"vi", yes, true},
		{"vi", no, false},
		{"code --wait", yes, false},
		{"", yes, false},
	} {
		got := hardenVim(c.cmd, c.isVim)
		if strings.HasSuffix(got, vimFlags) != c.want || !strings.HasPrefix(got, c.cmd) {
			t.Errorf("hardenVim(%q) = %q", c.cmd, got)
		}
	}
}

// script returns an editor command that copies the given contents into the
// file on successive runs.
func script(t *testing.T, contents ...string) string {
	t.Helper()
	dir := t.TempDir()
	for i, c := range contents {
		if err := os.WriteFile(filepath.Join(dir, string(rune('1'+i))), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return `d=` + dir + `; n=$(cat "$d/n" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$d/n"; cp_() { [ ! -f "$d/$n" ] || cp "$d/$n" "$1"; }; cp_`
}

func validate(b []byte) error {
	if bytes.Contains(b, []byte("bad")) {
		return errors.New("contains bad")
	}
	return nil
}

func TestEdit(t *testing.T) {
	var out bytes.Buffer
	e := &Editor{Command: script(t, "bad", "good"), In: strings.NewReader("r\n"), Out: &out}
	got, changed, err := e.Edit([]byte("initial"), validate)
	if err != nil || !changed || string(got) != "good" {
		t.Fatalf("got %q changed %v err %v", got, changed, err)
	}
	if !strings.Contains(out.String(), "contains bad") {
		t.Fatalf("output %q", out.String())
	}

	e = &Editor{Command: script(t, "bad"), In: strings.NewReader("a\n"), Out: &out}
	if _, _, err := e.Edit([]byte("initial"), validate); !errors.Is(err, ErrAborted) {
		t.Fatalf("err = %v, want ErrAborted", err)
	}

	// EOF on the prompt aborts too.
	e = &Editor{Command: script(t, "bad"), In: strings.NewReader(""), Out: &out}
	if _, _, err := e.Edit([]byte("initial"), validate); !errors.Is(err, ErrAborted) {
		t.Fatalf("err = %v, want ErrAborted", err)
	}

	e = &Editor{Command: script(t), Out: &out}
	if got, changed, err := e.Edit([]byte("same"), validate); err != nil || changed || string(got) != "same" {
		t.Fatalf("unchanged: %q %v %v", got, changed, err)
	}

	e = &Editor{Command: "false", Out: &out}
	if _, _, err := e.Edit([]byte("x"), validate); err == nil {
		t.Fatal("failing editor not reported")
	}
}
