package key

import (
	"github.com/dedis/kyber/share/dkg/pedersen"
)

// SharedPrivate holds a private share of a distributed secret key
type SharedPrivate struct {
	KeyID    string            // public key id
	FullName string            // full name as in the public key
	Email    string            // email as in the public key
	Extra    string            // extra info. as in public key
	Share    *dkg.DistKeyShare // the private share
}
