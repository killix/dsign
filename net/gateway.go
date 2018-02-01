package net

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net/transport"
	"github.com/nikkolasg/slog"
)

// Gateway is the gateway between dsign and the rest of the world. It enables to
// send messages and to receive messages. It uses a given underlying transport
// for its communication. For the moment,
type Gateway interface {
	// Gateway uses an underlying transport mechanism. Note that if you use any
	// function of the transport itself directly, the Gateway is not
	// responsible and do not manage any connection made this way.
	Transport() transport.Transport
	// Send sends a message to the given peer represented by this identity.
	Send(to *key.Identity, msg []byte) error
	// Start runs the Transport. The given Processor will be handled any new
	// incoming packets from the Transport. It is a non blocking call.
	Start(Processor) error
	// Stop closes all conections and stop the listening
	Stop() error
}

// Processor is a function that receives messages from the network
type Processor func(from *key.Identity, msg []byte)

type gateway struct {
	transport transport.Transport

	conns map[string]net.Conn

	processor Processor

	closed bool
	wg     sync.WaitGroup // to count all goroutines started
	sync.Mutex
}

// NewGateway returns a default gateway using the underlying given transport
// implementation.
func NewGateway(t transport.Transport) Gateway {
	return &gateway{
		transport: t,
		conns:     make(map[string]net.Conn),
	}
}

func (g *gateway) Send(to *key.Identity, msg []byte) error {
	g.Lock()
	var err error
	conn, ok := g.conns[to.ID]
	if !ok {
		conn, err = g.transport.Dial(to)
		if err != nil {
			g.Unlock()
			return err
		}
		go g.listenIncoming(to, conn)
	}
	g.Unlock()
	return sendBytes(conn, msg)
}

func (g *gateway) listenIncoming(remote *key.Identity, c transport.Conn) {
	g.Lock()
	g.conns[remote.ID] = c
	g.Unlock()
	g.wg.Add(1)
	defer g.wg.Done()
	for !g.isClosed() {
		buff, err := rcvBytes(c)
		if err != nil {
			slog.Debugf("gateway: error receiving from %s: %s\n", remote.Address, err)
			return
		}
		if g.processor == nil {
			continue
		}
		// XXX maybe switch to a consumer/producer style if needed
		g.processor(remote, buff)
	}
}

func (g *gateway) Start(h Processor) error {
	if g.processor != nil {
		return errors.New("router only supports one handler registration")
	}
	g.processor = h
	go g.transport.Listen(g.listenIncoming)
	return nil
}

func (g *gateway) Stop() error {
	g.Lock()
	defer g.Unlock()
	g.closed = true
	for _, c := range g.conns {
		if err := c.Close(); err != nil {
			return err
		}
	}
	if err := g.transport.Close(); err != nil {
		return err
	}
	g.wg.Wait()
	g.conns = make(map[string]net.Conn)
	return nil
}

func (g *gateway) Transport() transport.Transport {
	return g.transport
}

func (g *gateway) isClosed() bool {
	g.Lock()
	defer g.Unlock()
	return g.closed
}

func sendBytes(c net.Conn, b []byte) error {
	packetSize := len(b)
	if packetSize > MaxPacketSize {
		return fmt.Errorf("sending too much (%d bytes) to %s", packetSize, c.RemoteAddr().String())
	}
	// first write the size
	if err := binary.Write(c, globalOrder, uint32(packetSize)); err != nil {
		return err
	}

	// then send everything through the connection
	// send chunk by chunk
	var sent int
	for sent < packetSize {
		n, err := c.Write(b[sent:])
		if err != nil {
			return err
		}
		sent += n
	}
	return nil
}

func rcvBytes(c net.Conn) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(readTimeout))
	// First read the size
	var total uint32
	if err := binary.Read(c, globalOrder, &total); err != nil {
		return nil, err
	}
	if total > MaxPacketSize {
		return nil, fmt.Errorf("too big packet (%d bytes) from %s", total, c.RemoteAddr().String())
	}

	b := make([]byte, total)
	var buffer bytes.Buffer
	var read uint32
	for read < total {
		// read the size of the next packet.
		c.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := c.Read(b)
		// quit if there is an error.
		if err != nil {
			return nil, err
		}
		// append the read bytes into the buffer.
		if _, err := buffer.Write(b[:n]); err != nil {
			return nil, err
		}
		b = b[n:]
		read += uint32(n)
	}
	return buffer.Bytes(), nil
}

// a connection will return an io.EOF after readTimeout if nothing has been
// sent.
var readTimeout = 1 * time.Minute

// MaxPacketSize represents the maximum number of bytes can we receive or write
// to a net.Conn in bytes.
const MaxPacketSize = 1300

// globalOrder is the endianess used to write the size of a message.
var globalOrder = binary.BigEndian
