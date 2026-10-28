// Command av (age-env) encrypts, edits, prints and exports .env files with age.
package main

import (
	"os"
	"runtime/debug"

	"github.com/oneryx/av/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}
	os.Exit(cli.Main(version))
}
