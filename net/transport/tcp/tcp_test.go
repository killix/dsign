package tcp

import (
	"testing"
	"time"

	"github.com/nikkolasg/dsign/key"
	tr "github.com/nikkolasg/dsign/net/transport"
	"github.com/stretchr/testify/require"
)

// Test Listening with echo and connecting
func TestTcpTransport(t *testing.T) {
	message := []byte("mountainsofmadness")
	id1 := fakeID("127.0.0.1:8000")
	id2 := fakeID("127.0.0.1:8001")

	var _ tr.Transport = (*tcpTransport)(nil)
	t1 := NewTCPTransport(id1)
	t2 := NewTCPTransport(id2)

	handler := func(id *key.Identity, c tr.Conn) {
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
	time.Sleep(5 * time.Millisecond)

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

func fakeID(addr string) *key.Identity {
	return &key.Identity{Address: addr}
}
