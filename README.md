# av

`av` (short for age-env) keeps `.env` files encrypted with [age](https://github.com/FiloSottile/age), and lets you edit, read or export them from the terminal, or read them from Go code.

## Install

Download a binary for Linux or macOS (amd64/arm64) from the
[releases page](https://github.com/oneryx/av/releases), or build it:

```sh
go install github.com/oneryx/av/cmd/av@latest
# or, from a clone: go install ./cmd/av
# or: task build   (binary in bin/av; needs https://taskfile.dev)
```

### Releasing

Push a version tag; the `Release` workflow tests, builds and publishes a
GitHub release with archives and checksums ([.goreleaser.yaml](.goreleaser.yaml)):

```sh
git tag v0.0.2 && git push origin v0.0.2
```

## Usage

```sh
av encrypt .env                           # encrypt a file to .env.age (original kept)
av encrypt secrets.pem                    # encrypt a file to secrets.pem.age
av edit                                   # edit in $VISUAL / $EDITOR / vi, re-encrypt on quit
av get                                  # print the decrypted content
av get DATABASE_URL                       # print one value
av set DEBUG=1 API_KEY                    # set values; API_KEY is read without echo
av unset DEBUG
av run -- npm start                       # run a command with the variables in its environment
eval "$(av export)"                       # export the variables into the current shell
av recipients edit                      # edit the recipients file (recipients.txt)
av recipients get                     # print the recipients file
av help [command]                         # or: av COMMAND --help
av version
```

The encrypted file is the last argument, with no flag: `av get prod`, `av get KEY prod.env.age`. Flags may come before or after arguments, except with `av run`, where everything after the command is passed to it. For `run`, the file comes first: `av run prod.env.age -- npm start`.

- **Files:** the default is `./.env.age`. A `*.env.age` file holds `KEY=VALUE` lines. Any other `*.age` file (`secrets.age`) holds plain text: `get` (without a key), `edit` and the recipient commands work on both, while `get`, `set`, `unset`, `export` and `run` only accept env files. Other names get `.env.age` appended (`prod` → `prod.env.age`). For commands that take keys or a command, the file must end in `.age` (keys never contain dots), so write `prod.env.age` there.
- **Recipients:** `-r` and `-R` work as in `age` and apply to that command only. Otherwise files are encrypted to the public keys in `recipients.txt`, looked up in the current directory and then in `~/.config/age/`. `av recipients edit` changes it and does not re-encrypt anything: run `av edit` and save on each file afterwards. Every save prints who the file is encrypted to. Removing a recipient doesn't remove their access to old copies (such as git history), so rotate those secrets.
- **Identities:** pass them with `-i` (repeatable). Otherwise av uses whichever of `~/.config/age/keys.txt`, `~/Library/Application Support/age/keys.txt` (macOS), `~/.ssh/id_ed25519` and `~/.ssh/id_rsa` exist.
- **Validation (env files only):** each line must be blank, a `# comment`, or `[export ]KEY=VALUE`. Keys match `[A-Za-z_][A-Za-z0-9_]*`. Values may be unquoted, `'single'` or `"double"` quoted (``\n \t \r \" \\ \$ \` `` escapes). Variables like `$HOME` are **not** expanded. Duplicate keys are rejected. You can't save invalid content: `av edit` asks you to re-edit or abort.
- **Editing safety:** plaintext only lives in a private temp file (0600, in `/dev/shm` on Linux), which is removed on exit and on SIGTERM/SIGHUP. For vim and neovim, swap, backup, undo and viminfo files are turned off; other editors may keep their own backups. If the file is changed by someone else while you edit, `av` asks before overwriting it.
- **Armor:** files written by `age -a` (ASCII armor) can still be read; `av` rewrites them in age's normal binary format on the next save.

### `av run` vs `av export`

`av run -- cmd` gives the variables only to `cmd`. `eval "$(av export)"` puts them in your shell, where every later command can see them. Prefer `av run`.

To make `av export` work without `eval`, add this to `~/.zshrc` or `~/.bashrc`:

```sh
av() { if [ "$1" = export ]; then eval "$(command av "$@")"; else command av "$@"; fi; }
```

### Go library

Applications can read the same files without shelling out to `av`:

```go
import "github.com/oneryx/av"

vars, err := av.Read("")       // decrypt ./.env.age into a map[string]string
err = av.Load("prod.env.age")  // or set them in the environment (existing variables win)
text, err := av.Decrypt("secrets.age") // any other .age file, as raw bytes
```

Identities are found the same way as for `av`, unless you pass `av.WithIdentityFiles(...)` or `av.WithIdentityData(...)` (e.g. a key from a secret manager). A missing file gives an error matching `fs.ErrNotExist`, so you can make the file optional.

### Shell completion

```sh
source <(av completion zsh)   # add to ~/.zshrc; also bash, fish, powershell
```

The file argument completes `*.age` files.
