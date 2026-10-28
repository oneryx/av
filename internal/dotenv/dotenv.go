// Package dotenv parses and validates .env files.
//
// Accepted syntax, one entry per line:
//
//	# comment
//	KEY=value
//	export KEY=value
//	KEY="double quoted, supports \" \\ \n \t \r \$ \` escapes"
//	KEY='single quoted, literal'
//	KEY=value # inline comment (unquoted values need whitespace before #)
//
// Keys must match [A-Za-z_][A-Za-z0-9_]*. Blank lines are ignored, duplicate
// keys are rejected and values cannot span multiple lines. Variables such as
// $HOME are never expanded.
package dotenv

import (
	"fmt"
	"strings"
)

// Entry is a single KEY=VALUE pair.
type Entry struct {
	Key   string
	Value string
	Line  int
}

// LineError describes an invalid line.
type LineError struct {
	Line int
	Text string
	Msg  string
}

func (e LineError) Error() string {
	return fmt.Sprintf("line %d: %s: %s", e.Line, e.Msg, e.Text)
}

// ValidationError is returned by Validate when one or more lines are invalid.
type ValidationError []LineError

func (e ValidationError) Error() string {
	lines := make([]string, len(e))
	for i, le := range e {
		lines[i] = le.Error()
	}
	return strings.Join(lines, "\n")
}

// Parse parses content and returns all valid entries together with errors for
// every invalid line.
func Parse(content string) ([]Entry, []LineError) {
	var entries []Entry
	var errs []LineError
	seen := map[string]int{}

	for i, raw := range strings.Split(content, "\n") {
		n := i + 1
		raw = strings.TrimSuffix(raw, "\r")
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fail := func(msg string) { errs = append(errs, LineError{Line: n, Text: raw, Msg: msg}) }

		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimSpace(rest)
		}

		key, rawValue, ok := strings.Cut(line, "=")
		if !ok {
			fail("expected KEY=VALUE")
			continue
		}
		key = strings.TrimSpace(key)
		if !validKey(key) {
			fail(fmt.Sprintf("invalid key %q (must match [A-Za-z_][A-Za-z0-9_]*)", key))
			continue
		}
		value, err := parseValue(strings.TrimSpace(rawValue))
		if err != nil {
			fail(err.Error())
			continue
		}
		if prev, dup := seen[key]; dup {
			fail(fmt.Sprintf("duplicate key %q (first defined on line %d)", key, prev))
			continue
		}
		seen[key] = n
		entries = append(entries, Entry{Key: key, Value: value, Line: n})
	}
	return entries, errs
}

// Validate returns a ValidationError if content contains invalid lines.
func Validate(content []byte) error {
	if _, errs := Parse(string(content)); len(errs) > 0 {
		return ValidationError(errs)
	}
	return nil
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i, c := range k {
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func parseValue(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	switch v[0] {
	case '"':
		var b strings.Builder
		for i := 1; i < len(v); i++ {
			c := v[i]
			switch c {
			case '"':
				return b.String(), checkTrailing(v[i+1:])
			case '\\':
				if i+1 >= len(v) {
					return "", fmt.Errorf("unterminated double quote")
				}
				i++
				switch v[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case 'r':
					b.WriteByte('\r')
				case '"', '\\', '$', '`':
					b.WriteByte(v[i])
				default:
					b.WriteByte('\\')
					b.WriteByte(v[i])
				}
			default:
				b.WriteByte(c)
			}
		}
		return "", fmt.Errorf("unterminated double quote")
	case '\'':
		end := strings.IndexByte(v[1:], '\'')
		if end < 0 {
			return "", fmt.Errorf("unterminated single quote")
		}
		return v[1 : end+1], checkTrailing(v[end+2:])
	default:
		// Strip an inline comment: whitespace followed by '#'.
		for i := 1; i < len(v); i++ {
			if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
				return strings.TrimSpace(v[:i]), nil
			}
		}
		return v, nil
	}
}

// checkTrailing ensures only whitespace or a comment follows a quoted value.
func checkTrailing(rest string) error {
	trimmed := strings.TrimSpace(rest)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "#") && rest[0] != '#' {
		return nil
	}
	return fmt.Errorf("unexpected characters after closing quote")
}

// ShellQuote quotes s for safe use in a POSIX shell.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ExportScript renders entries as POSIX shell export statements.
func ExportScript(entries []Entry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "export %s=%s\n", e.Key, ShellQuote(e.Value))
	}
	return b.String()
}

// Set sets key to value in content. An existing line for key is replaced in
// place (keeping a leading "export"); otherwise a line is appended. content
// must be valid.
func Set(content, key, value string) (string, error) {
	if !validKey(key) {
		return "", fmt.Errorf("invalid key %q (must match [A-Za-z_][A-Za-z0-9_]*)", key)
	}
	entries, errs := Parse(content)
	if len(errs) > 0 {
		return "", ValidationError(errs)
	}
	line := key + "=" + Quote(value)
	for _, e := range entries {
		if e.Key == key {
			lines := strings.Split(content, "\n")
			if strings.HasPrefix(strings.TrimSpace(lines[e.Line-1]), "export") {
				line = "export " + line
			}
			lines[e.Line-1] = line
			return strings.Join(lines, "\n"), nil
		}
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + line + "\n", nil
}

// Unset removes the lines defining keys from content and returns the keys
// that were not present. content must be valid.
func Unset(content string, keys ...string) (string, []string, error) {
	entries, errs := Parse(content)
	if len(errs) > 0 {
		return "", nil, ValidationError(errs)
	}
	drop := map[int]bool{}
	var missing []string
	for _, k := range keys {
		found := false
		for _, e := range entries {
			if e.Key == k {
				drop[e.Line-1] = true
				found = true
			}
		}
		if !found {
			missing = append(missing, k)
		}
	}
	var out []string
	for i, l := range strings.Split(content, "\n") {
		if !drop[i] {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n"), missing, nil
}

// Quote formats value for the right-hand side of a KEY=VALUE line, quoting
// it only when needed.
func Quote(value string) string {
	plain := value != ""
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_-./:@%+,=", c)) {
			plain = false
			break
		}
	}
	if plain || value == "" {
		return value
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`, `$`, `\$`, "`", "\\`")
	return `"` + r.Replace(value) + `"`
}
