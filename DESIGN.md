# av design

`av` keeps `.env` files encrypted with [age](https://age-encryption.org) so they
can be committed, and lets you edit, read and use them from the terminal. This
document is a map of the code: what lives where, how the pieces fit together
and which rules must not be broken. Read it before changing anything; it should
tell you which file to open.

## Packages

```
av.go               public library (package av): Read/Load an encrypted .env for other Go programs
cmd/av/main.go          entry point: works out the version, calls cli.Main
internal/cli            commands, flags, identity and recipient policy  (depends on all below)
internal/identity       which identities to use: explicit, default paths
internal/crypt          thin wrapper around filippo.io/age: encrypt, decrypt, keys, atomic writes
internal/dotenv         parse, validate, edit and shell-quote .env content
internal/editor         run $EDITOR on a private temp file, loop until content is valid
internal/tty            hidden input on /dev/tty (values for `set KEY`)
```

Dependencies point one way: `cli` → `identity`, `crypt`, `dotenv`, `editor`,
`tty`, and `av` → `identity`, `crypt`, `dotenv`; `identity` → `crypt`.
`cli` and `av` don't import each other. The lower packages know nothing
about the CLI: no flag names, no hints like "pass -i" in their errors. That
policy belongs in `cli` (see `identities.go`, `noIdentityHint`). The one
exception is `identity`, which decides the default key locations so the CLI and
the library find keys the same way.

### Library (`av.go`)
`Read(path, opts...)` → `os.ReadFile` (errors wrapped with `%w`, so missing
files match `fs.ErrNotExist`) → `crypt.Decrypt` with `identity.Load(files,
data)` → `dotenv.Parse` → map. `Load` sets each variable that isn't
already set. Rules: the library **never prompts**, and its errors **never
contain line text** from the file, only line numbers and reasons, since library
errors end up in logs. This is a public, semver'd API: keep it small, and keep
`crypt`/`dotenv` types out of it.

Third-party code: `filippo.io/age` (crypto), `golang.org/x/crypto/ssh` (SSH
keys), `golang.org/x/term` (no-echo input), `spf13/cobra` + `pflag` (CLI).

## `internal/cli` file map

| File | Contents |
|---|---|
| `cli.go` | `CLI` struct (injected streams and editor), `Run` (error → exit code), root command, command groups, `help`/`version` commands, `confirm` prompt |
| `flags.go` | `options` (every flag of every command), `add*Flag` helpers, file-argument helpers (`fileArg`, `withFile`, `takeFile`), positional-argument validators, `EncPath`, small helpers |
| `cmd_edit.go` | `encrypt`, `edit`, `set`, `unset`, plus `readValue` (hidden input for `set KEY`) |
| `cmd_use.go` | `get`, `export`, `run` (`runWithEnv`: child process, signal forwarding, exit status) |
| `cmd_access.go` | `recipients [get\|edit]` |
| `update.go` | `update`, the read-modify-write pipeline; `decrypt`; `entries` |
| `target.go` | `target` (who to encrypt to), choosing it (`explicitTarget`, `newTarget`), the recipients file lookup, `save` |
| `identities.go` | `loadIdentities` (`-i`, else `identity.Load`), `noIdentityHint` |
| `cli_test.go` | end-to-end tests through `CLI.Run` |

Each command is a method `func (c *CLI) xxxCmd() *cobra.Command` that owns its
own `options` value, registers its flags and returns the command. Longer
command bodies are split into `runXxx` methods.

## Core flows

### Reading: `get`, `export`, `run`
`options.decrypt(path)` → `crypt.Decrypt`. For `get`, `export` and `run`,
`options.entries()` also parses the content with `dotenv.Parse` and refuses
files with invalid lines.

`crypt.Decrypt` looks at the age header. Passphrase (scrypt) files are refused
with an error. Any other file loads identities **lazily** through a callback,
so key files are only read when needed.

### Changing: `edit`, `set`, `unset`
All of them go through **`CLI.update(o, path, resolve, change)`** in
`update.go`:

1. decrypt, keeping the original ciphertext bytes;
2. `resolve()` → the `target` to encrypt to, and whether to save even if
   the content didn't change (`edit` always saves, so it picks up new recipients);
3. `change(plain)` → the new content and whether it changed;
4. if nothing changed and saving isn't forced (`set`, `unset`): print "No changes" and stop;
5. **lost-update check**: re-read the file and, if its bytes differ from
   step 1, ask before overwriting;
6. `save`.

To add another command that modifies a file, write a `resolve` (usually
`keepTarget(o)`) and a `change` func. Don't write your own
decrypt/encrypt sequence.

### Creating: `encrypt`
`runEncrypt`: refuse if `FILE.age` exists (unless `--force`) → read `FILE`
(validated if it's an env file) → `newTarget` → `save`. There's no
lost-update check because there's no previous version.

### Targets: who a file is encrypted for (`target.go`)
`target{recipients, lines}`.

* `explicitTarget`: `-r`/`-R`, for this command only. Returns `ok=false` when
  neither flag was given.
* `newTarget` (new files, and existing files on edit/set/unset):
  explicit flags → the recipients file (`loadRecipients`) if it exists → the
  public key of the user's first identity.
  Age files don't reveal their recipients, so a missing recipients file
  silently means "your own key"; the save output lists who the file is for.

Only `recipients edit` writes the recipients file. Encryption reads
it via `findRecipients` (`./recipients.txt`, then `~/.config/age/recipients.txt`).
`save` writes the encrypted file atomically and **prints the recipients**;
nothing else is written next to the file.

### Identities (`internal/identity`)
`identity.Load(files, data)`, used by `cli` (files = `-i`) and `av`
(`WithIdentityFiles`/`WithIdentityData`). Order: explicit files/data (strict) →
default paths (`~/.config/age/keys.txt`, macOS Application Support,
`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`), where missing or unreadable files are
skipped silently. Files are parsed by `crypt.LoadIdentityFile`, which handles
age keys and plain SSH keys. Passphrase-protected age identity files and
passphrase-protected SSH keys are refused with an error (and skipped in the
default locations).

### Editor (`internal/editor`)
`Editor.Edit(initial, validate)` writes a 0600 file in a private `MkdirTemp`
directory (`/dev/shm` on Linux), runs `sh -c "$CMD \"$@\""` (`Editor.Command`,
default `$VISUAL`/`$EDITOR`/vi; so `code --wait` works), and loops: if the
content is invalid, it asks "[r]e-edit or [a]bort?" on `In`. For vim and neovim
it appends `vimFlags` (no swap, backup, undo or viminfo files); plain `vi` gets
them only if `vi --version` says it's vim. A signal handler removes the temp
directory on SIGTERM/SIGHUP (and on SIGINT when the editor isn't running) and
exits 130.

## File formats

* **`X.env.age`**: a standard age file, binary, no armor. `age -d` can
  decrypt it. Armored files (from `age -a`) are still read and are rewritten
  as binary on the next save. Mode 0600.
* **`recipients.txt`** (`./recipients.txt`, else `~/.config/age/recipients.txt`;
  shared by all files): one recipient per line (`age1…`, `ssh-ed25519 …`,
  `ssh-rsa …`, `age1pq1…`, `age1tag1…`), `#` comments. Public keys only; meant
  to be committed. Mode 0644. Written by `av recipients edit`.
* **Plaintext** (`dotenv`): `[export ]KEY=VALUE` lines, `#` comments, single
  quotes (literal), double quotes (`\n \t \r \" \\ \$ \``), unquoted values
  with ` #` inline comments, no `$VAR` expansion, duplicate keys rejected.
  `EncPath` keeps any file name ending in `.age` as is (text file unless
  it ends in `.env.age`) and appends `.env.age` to the rest. Only env files
  get `dotenv` validation and the KEY=VALUE commands (`requireEnv`).

## Invariants (don't break these)

1. Plaintext never touches disk except in the editor's private temp
   directory, and that directory is always removed (`defer` plus the signal
   handler).
2. No invalid `.env` content is ever encrypted (`encrypt`, `edit` and `set`
   validate; `dotenv.Set`/`Unset` refuse invalid input).
3. Encrypted files are only written by `crypt.WriteFileAtomic` (temp file,
   fsync, rename; symlinks are followed).
4. Every successful save says who can decrypt the file.
5. Re-encrypting an existing file uses the recipients it gets now, unless the
   user passes `-r`/`-R` for that command.
6. Secret input (`set KEY`) reads `/dev/tty`, never stdin or stdout, so
   `eval "$(av export)"` and pipes keep working.
7. Lower packages stay free of CLI policy (see Packages).

## Errors and exit codes

`CLI.Run` maps the error a command returns:

| Error | Exit | Output |
|---|---|---|
| `nil` | 0 | |
| `exitCode(n)` | n | none (the command already printed what it needed to; also used for `run`'s child status) |
| `usageError` (`usagef`, flag errors via `SetFlagErrorFunc`, the `noArgs`/`exactArgs`/`minArgs` validators) | 2 | `av: msg` plus the command's usage |
| anything else | 1 | `av: msg` |

Cobra's own error and usage printing is silenced (`SilenceErrors`,
`SilenceUsage`); `Run` does all of it. Unknown commands and help topics are
usage errors.

Output conventions: data goes to **stdout** (`get`, `export`,
`recipients get`); status messages ("Wrote …", warnings) go to **stderr**.

## CLI conventions

* Flags may come after arguments, except for `run`
  (`SetInterspersed(false)`), whose arguments belong to the child command.
* The encrypted file is a trailing positional argument (`fileArg`, `withFile`,
  `takeFile`), never a flag. Common flags: `-i/--identity` (repeatable), `-r`,
  `-R`. Use the `add*Flag` helpers so names and help text stay identical across
  commands.
* Repeatable flags use `StringArray`, not `StringSlice`: no comma
  splitting, because recipients and paths may contain commas.
* A backticked word in a flag's help text becomes its placeholder in
  `--help`.

## Testing

* `cli_test.go` runs real commands through `CLI.Run` with injected streams.
  `setup` creates a temp dir (`t.Chdir`) with `HOME` set to it, an age key at
  `~/.config/age/keys.txt`, and a fake editor passed as `CLI.Editor`.
  `editorWrites(...)` queues the content for each editor run, and
  `editorRunsHook(n, cmd)` runs a shell command during run n (used to simulate
  a concurrent change).
* `TestInteropWithAgeCLI` checks against the real `age` binary when it's
  installed.
* Run `task lint` (gofmt, vet, staticcheck, govulncheck) and `task test`
  (or `task test:race`).

## Build, CI and release

* `task build` / `task install` (`Taskfile.yml`) stamp the version from `git describe` via
  `-X main.version=…`. A plain `go build` falls back to Go's VCS version
  (`main.go`).
* `.github/workflows/ci.yml`: on pushes to `main` and on PRs, runs
  `task lint`, `task test:race` (Linux with `age` installed for the interop
  test, and macOS) and `task build`. Tool versions (staticcheck,
  govulncheck) are pinned in `Taskfile.yml`.
* `.github/dependabot.yml`: weekly grouped updates for Go modules and
  GitHub Actions.
* `.github/workflows/release.yml`: on `v*` tags, runs the tests and then
  GoReleaser (`.goreleaser.yaml`): static (`CGO_ENABLED=0`) linux/darwin ×
  amd64/arm64 binaries, version = the tag, `tar.gz` archives plus
  `checksums.txt`, published as a GitHub release. No Windows build: the
  editor and secret input need `sh` and `/dev/tty`.
* Try a release locally: `goreleaser release --snapshot --clean`, which
  writes to `dist/` (ignored by git).

## Recipes

* **New command:** add `xxxCmd()` to the right `cmd_*.go`, register it in
  `rootCmd` under a group, use `update` if it modifies a file, add a test in
  `cli_test.go` and update the command list in `TestHelpAndVersion` and the
  README.
* **New flag shared by several commands:** add a field to `options`, an
  `add*Flag` helper in `flags.go` and, if useful, completion in
  `completeFile` for file arguments.
* **New `.env` syntax:** `dotenv.Parse`/`parseValue`, then make sure
  `Quote` still round-trips (`TestQuote`) and `ExportScript` is still safe.
* **New recipient or key type:** `crypt.ParseRecipient` and
  `ParseIdentityData`/`parseAgeIdentities` (so `newTarget` can derive the
  public key).
* **New identity source:** `identity.Load` (affects both the CLI and the
  library), and update `rootLong`, the `av` package doc and the README.
