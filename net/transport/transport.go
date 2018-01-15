package transport

import (
	"errors"
	"net"

	"github.com/nikkolasg/dsign/key"
)

// Transport is an abstraction to operate different kind of underlying network
// transport. A connection in a transport is designated through a string Address
// which is transport specific.  Note that a given Transport implementation
// might use two or more underlying Transport.
type Transport interface {
	Dial(*key.Identity) (net.Conn, error)
	Listen(*key.Identity, Handler) error
	Close() error
}

// Handler is a function that operates under an incoming connection with the
// given Address. Address is transport specific.
type Handler func(i *key.Identity, conn net.Conn)

var ErrTransportClosed = errors.New("transport already closed")
