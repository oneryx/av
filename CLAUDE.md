# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`av` keeps `.env` files encrypted with age (`.env.age`): a CLI (`cmd/av`, `internal/cli`) plus a small public Go library (`av.go`) that reads the same files. README.md covers usage; **DESIGN.md is the code map. Read it before changing anything**: package layout, the `update` pipeline for modifying files, the invariants, error/exit-code mapping and "add a new command/flag" recipes.

## Commands

Uses go-task (`Taskfile.yml`):

```sh
task build          # bin/av, version stamped from git describe
task test           # go test ./...
task test:race      # what CI runs
task lint           # gofmt check, go vet, staticcheck, govulncheck (pinned versions)
go test ./internal/cli -run TestName    # single test
```

`TestInteropWithAgeCLI` only runs fully if the real `age` binary is installed.

## Architecture essentials

- Dependencies point one way: `internal/cli` and `av` → `identity`, `crypt`, `dotenv` (`cli` also → `editor`, `tty`). `cli` and `av` never import each other. Lower packages contain no CLI policy (no flag names or "pass -i" hints in their errors); that lives in `internal/cli`.
- Every command that modifies an encrypted file goes through `CLI.update` (`internal/cli/update.go`: decrypt → resolve target → change → lost-update check → atomic save). Don't hand-roll decrypt/encrypt sequences.
- Encryption recipients come from `-r`/`-R`, else `recipients.txt` (`./` then `~/.config/age/`), else the user's own key (`internal/cli/target.go`).
- Library (`av.go`) is public and semver'd: keep it small, never prompt, never put file line contents in errors.

## Invariants

- Plaintext only exists in the editor's private temp dir, always removed.
- Invalid `.env` content is never encrypted.
- Encrypted files are written only via `crypt.WriteFileAtomic`.
- Every successful save prints who can decrypt the file.
- `set KEY` reads secrets from `/dev/tty`, never stdin/stdout.
- Data goes to stdout, status messages to stderr. `run` passes everything after the command to the child (`SetInterspersed(false)`).

## Testing

`internal/cli/cli_test.go` runs real commands through `CLI.Run` with injected streams, a temp `HOME` and a fake editor (`editorWrites`, `editorRunsHook`). Tests must never touch the real `.env.age` in the repo root or the user's real config.

## Release

Push a `v*` tag; GitHub Actions runs GoReleaser (`.goreleaser.yaml`) for linux/darwin × amd64/arm64. Public GitHub project: no Gitea/server/host details in the repo or docs.
