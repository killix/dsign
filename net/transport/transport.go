package transport

import (
	"errors"
	"net"
)

// Transport is an abstraction to operate different kind of underlying network
// transport. A connection in a transport is designated through a string ID
// which is transport specific.
type Transport interface {
	Dial(id ID) (net.Conn, error)
	Listen(Handler) error
	Close() error
}

// Handler is a function that operates under an incoming connection with the
// given ID. ID is transport specific.
type Handler func(id ID, conn net.Conn)

// ID is a generic identifier for a remote peer depending on the underlying
// transport.
type ID struct {
	// Type is the type of transport being used to communicate with the remote
	// peer
	Type TypeID
	// Val is the actual value of the ID. For TCP, it is the IP address of the
	// remote peer, for Channel based transport it is the channel's ID.
	Val string
}

// TypeID represents the different types that an ID can hold.
type TypeID byte

const (
	// TCP based connection
	TCP TypeID = iota
	// Channel based connection
	Channel
)

var ErrWrongTypeID = errors.New("wrong type of connection given")
var ErrTransportClosed = errors.New("transport already closed")
