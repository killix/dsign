package dkg

import (
	"github.com/dedis/kyber/share/dkg/pedersen"
)

// Packet holds a message sent during a DKG protocol execution.
type Packet struct {
	Deal     *dkg.Deal
	Response *dkg.Response
	// XXX Not implemented yet
	Justification *dkg.Justification
}
