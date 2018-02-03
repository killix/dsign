package core

import (
	"github.com/nikkolasg/dsign/dkg"
	"github.com/nikkolasg/dsign/dss"
	"github.com/nikkolasg/dsign/net"
)

// encoder marshals and unmarshals ProtocolPacket protobuf encoded
var encoder = net.NewSingleProtoEncoder(&ProtocolPacket{})

// ProtocolPacket contains all sub packets for the different sub protocols to
// run
type ProtocolPacket struct {
	NewKeyPair   *NewKeyPair   // creation of a new longterm keypair
	NewSignature *NewSignature // creation of a new signature
}

// NewKeyPair contains all packets used to create a new longterm key pair
type NewKeyPair struct {
	SessionID []byte            // ties a newkeypair request with a session id
	Proposal  *LongtermProposal // gives information about the new key to create
	Longterm  *dkg.Packet       // runs the dkg protocol to create the longterm key
	Signing   *Signing          // runs the dist. signing protocol over the longterm key
}

// LongtermProposal contains the relevant information to put in the key identity
type LongtermProposal struct {
	FullName string // fullname as described in pgp keys
	Email    string // email as described in pgp keys
	Extra    string // generic extra information to be shown before validation
}

// NewSignature contains all packets used to create a new distributed signature
// over a message.
type NewSignature struct {
	SessionID []byte         // ties a newsignature request with a session id
	Info      *SignatureInfo // get the information about what to sign
	Signing   *Signing       // runs the dist. signing protocol for this message
}

// SignatureInfo contains all information about the message to sign
type SignatureInfo struct {
	KeyID   string
	Type    uint32 // type of message
	Message string // message to sign => dependant of type, may be only an accessor
}

// Signing packets is sent to compute a distributed signature (either over a
// key, i.e. a self signature, or over a message.
type Signing struct {
	SessionID []byte      // ties a signing request with a session id
	Random    *dkg.Packet // packet to generate a random distributed key
	Signature *dss.Packet // packet to generate a distributed signature
}
