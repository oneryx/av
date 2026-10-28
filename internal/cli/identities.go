package cli

import (
	"github.com/oneryx/av/internal/crypt"
	"github.com/oneryx/av/internal/identity"
	"github.com/oneryx/av/internal/tty"
)

const noIdentityHint = "no identity found: pass -i, set " + identity.FilesEnv + " or " + identity.DataEnv + ", or create ~/.config/age/keys.txt"

func readPrompt(prompt string) ([]byte, error) { return tty.ReadSecret(prompt) }

// loadIdentities loads identities from -i, else from $AV_IDENTITY_DATA and
// $AV_IDENTITY, else from the default locations (see identity.Load).
func (o *options) loadIdentities() ([]crypt.Identity, error) {
	return identity.Load(o.identities, nil, readPrompt)
}
