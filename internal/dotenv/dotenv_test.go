package dotenv

import (
	"os/exec"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	in := strings.Join([]string{
		"# comment",
		"",
		"KEY1=VALUE1",
		"  export KEY2 = value two  ",
		`KEY3="a \"quoted\" \\ value\nnext" # trailing comment`,
		`KEY4='single $NOT #expanded'`,
		"KEY5=",
		"KEY6=pass#word",
		"KEY7=value # comment",
		"_K8=x=y=z",
		"exported=1",
		"WIN=crlf\r",
	}, "\n")
	entries, errs := Parse(in)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	want := map[string]string{
		"KEY1":     "VALUE1",
		"KEY2":     "value two",
		"KEY3":     "a \"quoted\" \\ value\nnext",
		"KEY4":     "single $NOT #expanded",
		"KEY5":     "",
		"KEY6":     "pass#word",
		"KEY7":     "value",
		"_K8":      "x=y=z",
		"exported": "1",
		"WIN":      "crlf",
	}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(entries), len(want), entries)
	}
	for _, e := range entries {
		if want[e.Key] != e.Value {
			t.Errorf("%s = %q, want %q", e.Key, e.Value, want[e.Key])
		}
	}
}

func TestParseInvalid(t *testing.T) {
	cases := map[string]string{
		"no equals":        "JUSTAKEY",
		"empty key":        "=value",
		"digit first":      "1KEY=v",
		"dash in key":      "MY-KEY=v",
		"space in key":     "MY KEY=v",
		"unterminated dq":  `K="abc`,
		"unterminated sq":  `K='abc`,
		"garbage after dq": `K="abc"def`,
		"garbage after sq": `K='abc'def`,
		"export only":      "export",
		"dangling escape":  `K="abc\`,
		"hash right after": `K="abc"#x`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			_, errs := Parse(line)
			if len(errs) != 1 || errs[0].Line != 1 {
				t.Fatalf("Parse(%q) errors = %v, want one error on line 1", line, errs)
			}
		})
	}
}

func TestDuplicateKey(t *testing.T) {
	_, errs := Parse("A=1\nB=2\nA=3\n")
	if len(errs) != 1 || errs[0].Line != 3 || !strings.Contains(errs[0].Msg, "line 1") {
		t.Fatalf("errors = %v", errs)
	}
}

func TestValidateReportsAllLines(t *testing.T) {
	err := Validate([]byte("BAD\nOK=1\nALSO BAD=2\n"))
	verr, ok := err.(ValidationError)
	if !ok || len(verr) != 2 || verr[0].Line != 1 || verr[1].Line != 3 {
		t.Fatalf("Validate = %v", err)
	}
}

func TestExportScriptRoundTrip(t *testing.T) {
	entries := []Entry{
		{Key: "A", Value: "simple"},
		{Key: "B", Value: "it's got 'quotes' and \"doubles\""},
		{Key: "C", Value: "$HOME `whoami` $(id) \\ ;|&"},
		{Key: "D", Value: "multi\nline"},
		{Key: "E", Value: ""},
	}
	script := ExportScript(entries) + `printf '%s\0' "$A" "$B" "$C" "$D" "$E"`
	out, err := exec.Command("sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	for i, e := range entries {
		if got[i] != e.Value {
			t.Errorf("%s = %q, want %q", e.Key, got[i], e.Value)
		}
	}
}

func TestSetUnset(t *testing.T) {
	in := "# c\nA=1\nexport B=2\nC=3"
	got, err := Set(in, "B", `it's "x" $y`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := "# c\nA=1\nexport B=\"it's \\\"x\\\" \\$y\\n\"\nC=3"; got != want {
		t.Fatalf("Set = %q, want %q", got, want)
	}
	entries, errs := Parse(got)
	if len(errs) > 0 || entries[1].Value != `it's "x" $y`+"\n" {
		t.Fatalf("round trip: %+v %v", entries, errs)
	}
	got, _ = Set(got, "D", "plain/value:1")
	if !strings.HasSuffix(got, "C=3\nD=plain/value:1\n") {
		t.Fatalf("append = %q", got)
	}
	got, missing, err := Unset(got, "A", "D", "NOPE")
	if err != nil || len(missing) != 1 || missing[0] != "NOPE" {
		t.Fatalf("missing = %v, err = %v", missing, err)
	}
	if strings.Contains(got, "A=1") || strings.Contains(got, "D=") || !strings.Contains(got, "C=3") {
		t.Fatalf("Unset = %q", got)
	}
	if _, err := Set("BAD\n", "A", "1"); err == nil {
		t.Fatal("Set accepted invalid content")
	}
	if _, err := Set("", "1A", "1"); err == nil {
		t.Fatal("Set accepted invalid key")
	}
}

func TestQuote(t *testing.T) {
	for _, v := range []string{"", "simple", "with space", "a#b", " lead", "'q'", "\\", "multi\nline", "tab\t", "ünï"} {
		entries, errs := Parse("K=" + Quote(v))
		if len(errs) > 0 || entries[0].Value != v {
			t.Errorf("Quote(%q) = %s does not round-trip: %+v %v", v, Quote(v), entries, errs)
		}
	}
}
