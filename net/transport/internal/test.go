package internal

import (
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
	require.Nil(t, err)
	n1, err := c21.Write(message)
	require.Nil(t, err)
	var buff [32]byte
	n2, err := c21.Read(buff[:])
	require.Nil(t, err)
	require.Equal(t, n1, n2)

	require.Nil(t, t1.Close())

	select {
	case <-done:
		return
	case <-time.After(50 * time.Millisecond):
		t.Fatal("listening transport did not close?")
	}

}
