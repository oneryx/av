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
internal/identity       which identities to use: explicit, $AV_IDENTITY*, default paths
internal/crypt          thin wrapper around filippo.io/age: encrypt, decrypt, keys, atomic writes
internal/dotenv         parse, validate, edit and shell-quote .env content
internal/editor         run $EDITOR on a private temp file, loop until content is valid
internal/tty            prompts on /dev/tty (secrets, new passphrase)
```

Dependencies point one way: `cli` → `identity`, `crypt`, `dotenv`, `editor`,
`tty`, and `av` → `identity`, `crypt`, `dotenv`; `identity` → `crypt`.
`cli` and `av` don't import each other. The lower packages know nothing
about the CLI: no flag names, no hints like "pass -i" in their errors. That
policy belongs in `cli` (see `identities.go`, `noIdentityHint`). The one
exception is `identity`, which owns the `AV_IDENTITY*` variables so the CLI and
the library find keys the same way.

### Library (`av.go`)
`Read(path, opts...)` → `os.ReadFile` (errors wrapped with `%w`, so missing
files match `fs.ErrNotExist`) → `crypt.Decrypt` with `identity.Load(files,
data, prompt)` → `dotenv.Parse` → map. `Load` sets each variable that isn't
already set. Rules: the library **never prompts** on its own (no `/dev/tty`;
without `WithPassphrase`/`WithPrompt` it returns `ErrPassphraseRequired`), and
its errors **never contain line text** from the file, only line numbers and
reasons, since library errors end up in logs. This is a public, semver'd API:
keep it small, and keep `crypt`/`dotenv` types out of it.

Third-party code: `filippo.io/age` (crypto), `golang.org/x/crypto/ssh` (SSH
keys), `golang.org/x/term` (no-echo input), `spf13/cobra` + `pflag` (CLI).

## `internal/cli` file map

| File | Contents |
|---|---|
| `cli.go` | `CLI` struct (injected streams), `Run` (error → exit code), root command, command groups, `help`/`version` commands, `confirm` prompt |
| `flags.go` | `options` (every flag of every command), `add*Flag` helpers, flag completion, positional-argument validators, `EncPath`, small helpers |
| `cmd_edit.go` | `new`, `edit`, `set`, `unset`, plus `readValue` (hidden input for `set KEY`) |
| `cmd_use.go` | `print`, `get`, `export`, `run` (`runWithEnv`: child process, signal forwarding, exit status) |
| `cmd_access.go` | `recipients [list\|add\|rm]`, `rekey` |
| `update.go` | `update`, the read-modify-write pipeline; `decrypt`; `entries` |
| `target.go` | `target` (how to encrypt), choosing it (`explicitTarget`, `newTarget`, `sameTarget`), recipients file read/write, `save` |
| `identities.go` | `loadIdentities` (`-i`, else `identity.Load`), the `/dev/tty` prompt, `noIdentityHint` |
| `cli_test.go` | end-to-end tests through `CLI.Run` |

Each command is a method `func (c *CLI) xxxCmd() *cobra.Command` that owns its
own `options` value, registers its flags and returns the command. Longer
command bodies are split into `runXxx` methods.

## Core flows

### Reading: `print`, `get`, `export`, `run`
`options.decrypt(path)` → `crypt.Decrypt`. For `get`, `export` and `run`,
`options.entries()` also parses the content with `dotenv.Parse` and refuses
files with invalid lines.

`crypt.Decrypt` looks at the age header. A passphrase (scrypt) file prompts
for the passphrase; any other file loads identities **lazily** through a
callback, so passphrase files never touch key files and key files are only
read when needed. It returns `crypt.Info`, which carries the passphrase so the
file can be re-encrypted with it later.

### Changing: `edit`, `set`, `unset`, `rekey`, `recipients add|rm`
All of them go through **`CLI.update(o, path, resolve, change)`** in
`update.go`:

1. decrypt, keeping the original ciphertext bytes;
2. `resolve(info)` → the `target` to encrypt to, and whether to save even if
   the content didn't change (recipient changes, rekey);
3. `change(plain)` → the new content and whether it changed;
4. if nothing changed and saving isn't forced: print "No changes" and stop;
5. **lost-update check**: re-read the file and, if its bytes differ from
   step 1, ask before overwriting;
6. `save`.

To add another command that modifies a file, write a `resolve` (usually
`keepTarget(path, force)`) and a `change` func. Don't write your own
decrypt/encrypt sequence.

### Creating: `new`
`runNew`: refuse if the file exists (unless `--force`) → content from
`--from` (validated) or the editor → `newTarget` → `save`. There's no
lost-update check because there's no previous version.

### Targets: who a file is encrypted for (`target.go`)
`target{recipients, lines, writeSidecar}`. `lines == nil` means a passphrase.

* `explicitTarget`: `-p`, or `-r`/`-R` (written to the recipients file).
  Returns `ok=false` when none of these flags were given.
* `newTarget` (new files): explicit flags → an existing `<file>.recipients`
  → the public key of the user's first identity.
* `sameTarget` (existing files): keep the passphrase if the file has one,
  else use `<file>.recipients`; it's an error if that file is missing (age
  files don't reveal their recipients).

`save` encrypts, then **updates the recipients file before the encrypted
file** (it deletes the recipients file for passphrase targets), writes the
encrypted file atomically, and **prints the recipients**.

### Identities (`internal/identity`)
`identity.Load(files, data, prompt)`, used by `cli` (files = `-i`) and
`av` (`WithIdentityFiles`/`WithIdentityData`). Order: explicit
files/data (strict) → `$AV_IDENTITY_DATA` (key content) + `$AV_IDENTITY`
(`:`-separated paths), both strict → default paths (XDG/`~/.config/age/keys.txt`,
macOS Application Support, `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`), where
missing or unreadable files are skipped silently. Files are parsed by
`crypt.LoadIdentityFile`, which handles age keys, passphrase-encrypted age
identity files, plain SSH keys and passphrase-protected SSH keys (whose public
key comes from the key itself or from `<key>.pub`).

### Editor (`internal/editor`)
`Editor.Edit(initial, validate)` writes a 0600 file in a private `MkdirTemp`
directory (`/dev/shm` on Linux), runs `sh -c "$EDITOR \"$@\""` (so
`EDITOR="code --wait"` works), and loops: if the content is invalid, it asks
"[r]e-edit or [a]bort?" on `In`. For vim and neovim it appends `vimFlags` (no
swap, backup, undo or viminfo files); plain `vi` gets them only if
`vi --version` says it's vim. A signal handler removes the temp directory on
SIGTERM/SIGHUP (and on SIGINT when the editor isn't running) and exits 130.

## File formats

* **`X.env.age`**: a standard age file, binary, no armor. `age -d` can
  decrypt it. Armored files (from `age -a`) are still read and are rewritten
  as binary on the next save. Mode 0600.
* **`X.env.age.recipients`**: one recipient per line (`age1…`, `ssh-ed25519 …`,
  `ssh-rsa …`, `age1pq1…`, `age1tag1…`), `#` comments, first line is a
  "managed by av" header. Public keys only; meant to be committed. Mode 0644.
  Its absence means "passphrase file" or "unknown".
* **Plaintext** (`dotenv`): `[export ]KEY=VALUE` lines, `#` comments, single
  quotes (literal), double quotes (`\n \t \r \" \\ \$ \``), unquoted values
  with ` #` inline comments, no `$VAR` expansion, duplicate keys rejected.
  `EncPath` maps any `-f` value onto the `*.env.age` naming.

## Invariants (don't break these)

1. Plaintext never touches disk except in the editor's private temp
   directory, and that directory is always removed (`defer` plus the signal
   handler).
2. No invalid `.env` content is ever encrypted (`new`, `edit` and `set`
   validate; `dotenv.Set`/`Unset` refuse invalid input).
3. Encrypted files are only written by `crypt.WriteFileAtomic` (temp file,
   fsync, rename; symlinks are followed).
4. Every successful save says who can decrypt the file.
5. Re-encrypting an existing file keeps its passphrase or recipients unless
   the user passes `-r`/`-R`/`-p` or uses `recipients add|rm`.
6. Secret prompts read `/dev/tty`, never stdin or stdout, so
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

Output conventions: data goes to **stdout** (`print`, `get`, `export`,
`recipients list`); status messages ("Wrote …", warnings) go to **stderr**.

## CLI conventions

* Flags may come after arguments, except for `run`
  (`SetInterspersed(false)`), whose arguments belong to the child command.
* Common flags: `-f/--file`, `-i/--identity` (repeatable), `-r`, `-R`, `-p`.
  Use the `add*Flag` helpers so names and help text stay identical across
  commands, then call `registerCompletions(cmd)`.
* Repeatable flags use `StringArray`, not `StringSlice`: no comma
  splitting, because recipients and paths may contain commas.
* A backticked word in a flag's help text becomes its placeholder in
  `--help` (`` "encrypted `FILE`" `` shows as `--file FILE`).

## Testing

* `cli_test.go` runs real commands through `CLI.Run` with injected streams.
  `setup` creates a temp dir (`t.Chdir`), an age key in `$AV_IDENTITY` and
  a fake `$EDITOR` script. `editorWrites(...)` queues the content for each
  editor run, and `editorRunsHook(n, cmd)` runs a shell command during run n
  (used to simulate a concurrent change).
* `TestInteropWithAgeCLI` checks against the real `age` binary when it's
  installed.
* The passphrase paths need a terminal, so they're tested at the `crypt`
  level (prompt callbacks) and via `save` with `passphraseTarget` directly.
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
  editor and prompts need `sh` and `/dev/tty`.
* Try a release locally: `goreleaser release --snapshot --clean`, which
  writes to `dist/` (ignored by git).

## Recipes

* **New command:** add `xxxCmd()` to the right `cmd_*.go`, register it in
  `rootCmd` under a group, use `update` if it modifies a file, add a test in
  `cli_test.go` and update the command list in `TestHelpAndVersion` and the
  README.
* **New flag shared by several commands:** add a field to `options`, an
  `add*Flag` helper in `flags.go` and, if useful, completion in
  `registerCompletions`.
* **New `.env` syntax:** `dotenv.Parse`/`parseValue`, then make sure
  `Quote` still round-trips (`TestQuote`) and `ExportScript` is still safe.
* **New recipient or key type:** `crypt.ParseRecipient` and
  `parseIdentityData`/`parseAgeIdentities` (so `newTarget` can derive the
  public key).
* **New identity source:** `identity.Load` (affects both the CLI and the
  library), and update `rootLong`, the `av` package doc and the README.
