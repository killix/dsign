package internal

import (
	"crypto/rand"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net/transport"
	"github.com/stretchr/testify/require"
)

// TransportFactory is an interface that different transport implementation must
// fulfill to use the generic transport tests.
type TransportFactory interface {
	NewTransports(n int) ([]*key.Private, []transport.Transport)
}

// TestTransport operates a series of generic test for a given transport
// implementation.
func TestTransport(t *testing.T, factory TransportFactory) {
	message := []byte("mountainsofmadness")
	ids, trs := factory.NewTransports(2)
	t1, t2 := trs[0], trs[1]
	id1, _ := ids[0].Public, ids[1].Public

	handler := func(id *key.Identity, c transport.Conn) {
		var buff [32]byte
		n, err := c.Read(buff[:])
		require.Nil(t, err)
		_, err = c.Write(buff[:n])
		require.Nil(t, err)
		require.Nil(t, c.Close())
	}

	done := make(chan bool)

	go func() {
		err := t1.Listen(handler)
		require.Nil(t, err)
		done <- true
	}()
	time.Sleep(10 * time.Millisecond)

	c21, err := t2.Dial(id1)
	require.NoError(t, err)
	n1, err := c21.Write(message)
	require.NoError(t, err)
	var buff [32]byte
	n2, err := c21.Read(buff[:])
	require.NoError(t, err)
	require.Equal(t, n1, n2)

	require.NoError(t, t1.Close())

	select {
	case <-done:
		return
	case <-time.After(50 * time.Millisecond):
		t.Fatal("listening transport did not close?")
	}

}

// FakeID returns a random ID with the given address.
func FakeID(addr string) (*key.Private, *key.Identity) {
	priv, id, err := key.NewPrivateIdentityWithAddr(addr, rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, id
}

// Addresses returns a list of TCP localhost addresses starting from the given
// port= start.
func Addresses(start, n int) []string {
	addrs := make([]string, n, n)
	for i := 0; i < n; i++ {
		addrs[i] = "127.0.0.1:" + strconv.Itoa(GetFreePort())
	}
	return addrs
}

// GetFreePort returns an free TCP port.
// Taken from https://github.com/phayes/freeport/blob/master/freeport.go
func GetFreePort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// GenerateIDs returns n private keys with the start address given to Addresses
func GenerateIDs(start, n int) []*key.Private {
	keys := make([]*key.Private, n)
	addrs := Addresses(start, n)
	for i := range addrs {
		priv, _ := FakeID(addrs[i])
		keys[i] = priv
	}
	return keys
}
