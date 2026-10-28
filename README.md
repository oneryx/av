# av

`av` (short for age-env) keeps `.env` files encrypted with [age](https://github.com/FiloSottile/age), and lets you edit, print or export them from the terminal, or read them from Go code.

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
av new                                    # open $EDITOR, save .env.age encrypted to your own key
av new --from .env -r age1... -R team.txt # encrypt an existing .env to several recipients
av new -f prod -p                         # prod.env.age, encrypted with a passphrase
av edit                                   # edit in $VISUAL / $EDITOR / vi, re-encrypt on quit
av print                                  # print decrypted content
av get DATABASE_URL                       # print one value
av set DEBUG=1 API_KEY                    # set values; API_KEY is read without echo
av unset DEBUG
av run -- npm start                       # run a command with the variables in its environment
eval "$(av export)"                       # export the variables into the current shell
av recipients add ssh-ed25519 AAAA... bob # give bob access (re-encrypts)
av recipients rm bob                      # remove by key or SSH comment
av rekey                                  # re-encrypt for the current recipients file
av help [command]                         # or: av COMMAND --help
av version
```

Flags may come before or after arguments (`av get KEY -f prod`), except with `av run`, where everything after the command is passed to it.

- **Files:** the default is `./.env.age`. `-f NAME` always ends up as `*.env.age` (`-f prod` → `prod.env.age`).
- **Recipients:** `-r`, `-R` and `-p` work as in `age`. Recipients are stored in `<file>.recipients` (public keys only, safe to commit) and reused by `av edit`, `set`, `unset` and `rekey`. Every save prints who the file is encrypted to, so check it when someone else changed the recipients file. Passphrase files stay passphrase-encrypted on edit. Removing a recipient doesn't remove their access to old copies (such as git history), so rotate those secrets.
- **Identities:** pass them with `-i` (repeatable). Otherwise `av` uses `$AV_IDENTITY_DATA` (the content of an identity file, e.g. a CI secret) and `$AV_IDENTITY` (identity file paths separated by `:`), or whichever of `~/.config/age/keys.txt`, `~/Library/Application Support/age/keys.txt` (macOS), `~/.ssh/id_ed25519` and `~/.ssh/id_rsa` exist. SSH keys protected by a passphrase and passphrase-encrypted age identity files are supported.
- **Validation:** each line must be blank, a `# comment`, or `[export ]KEY=VALUE`. Keys match `[A-Za-z_][A-Za-z0-9_]*`. Values may be unquoted, `'single'` or `"double"` quoted (``\n \t \r \" \\ \$ \` `` escapes). Variables like `$HOME` are **not** expanded. Duplicate keys are rejected. You can't save invalid content: `av edit` asks you to re-edit or abort.
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
```

Identities are found the same way as for `av`, unless you pass `av.WithIdentityFiles(...)` or `av.WithIdentityData(...)` (e.g. a key from a secret manager). The library never prompts: passphrase-encrypted files and protected keys need `av.WithPassphrase` or `av.WithPrompt`. A missing file gives an error matching `fs.ErrNotExist`, so you can make the file optional.

### Shell completion

```sh
source <(av completion zsh)   # add to ~/.zshrc; also bash, fish, powershell
```

`-f` completes `*.age` files, and `av recipients rm` completes recipient names.
