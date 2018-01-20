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
	Dial(*key.Identity) (Conn, error)
	// Listen is a blocking call.
	Listen(Handler) error
	Close() error
}

// Conn is a simple alias for net.Conn to avoid msiconfusion with the regular
// golang package.
type Conn net.Conn

// Handler is a function alias for handling new incoming connection from a
// Transport. The Identity may be nil if the underlying transport do not support
// authentication (tcp for example).
type Handler func(i *key.Identity, conn Conn)

// ErrTransportClosed gets triggered when oen tries to send a message over a
// closed connection.
var ErrTransportClosed = errors.New("transport already closed")
