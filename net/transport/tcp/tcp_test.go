package tcp

import (
	"net"
	"testing"
	"time"

	"github.com/nikkolasg/dsign/key"
	"github.com/stretchr/testify/require"
)

// Test Listening with echo and connecting
func TestTcpTransport(t *testing.T) {
	message := []byte("mountainsofmadness")
	id1 := fakeId("127.0.0.1:8000")

	t1 := NewTcpTransport()
	t2 := NewTcpTransport()

	_, ok := t1.(Transport)
	require.True(t, ok)

	handler := func(id *key.Identity, c net.Conn) {
		var buff [32]byte
		n, err := c.Read(buff[:])
		require.Nil(t, err)
		_, err = c.Write(buff[:n])
		require.Nil(t, err)
		require.Nil(t, c.Close())
	}

	done := make(chan bool)

	go func() {
		err := t1.Listen(id1, handler)
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

func fakeId(addr string) *key.Identity {
	return &key.Identity{Address: addr}
}