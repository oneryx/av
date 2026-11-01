package cli

import (
	"github.com/oneryx/av/internal/crypt"
	"github.com/oneryx/av/internal/identity"
)

const noIdentityHint = "no identity found: pass -i, or create ~/.config/age/keys.txt"

// loadIdentities loads identities from -i, else from the default locations.
// The result is cached, so the identity files are read once per command.
func (o *options) loadIdentities() ([]crypt.Identity, error) {
	if o.idsLoaded {
		return o.ids, nil
	}
	ids, err := identity.Load(o.identities, nil)
	if err != nil {
		return nil, err
	}
	o.ids, o.idsLoaded = ids, true
	return ids, nil
}
