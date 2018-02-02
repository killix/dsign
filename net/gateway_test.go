package net

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net/transport/noise"
	"github.com/stretchr/testify/require"
)

func TestGateway(t *testing.T) {
	priv1, pub1 := FakeID("127.0.0.1:8000")
	priv2, pub2 := FakeID("127.0.0.1:8001")
	list := []*key.Identity{pub1, pub2}

	tr1 := noise.NewTCPNoiseTransport(priv1, list)
	g1 := NewGateway(priv1.Public, tr1)
	tr2 := noise.NewTCPNoiseTransport(priv2, list)
	g2 := NewGateway(priv2.Public, tr2)

	listenDone := make(chan bool)
	rcvDone := make(chan bool)
	sentDone := make(chan bool, 1)
	handler2 := func(from *key.Identity, msg []byte) {
		<-sentDone
		require.Nil(t, g2.Send(pub1, msg))
		listenDone <- true
	}
	handler1 := func(from *key.Identity, msg []byte) {
		require.Equal(t, []byte{0x2a}, msg)
		rcvDone <- true
	}

	require.Nil(t, g2.Start(handler2))
	require.Nil(t, g1.Start(handler1))

	time.Sleep(10 * time.Millisecond)
	msg := []byte{0x2a}
	err := g1.Send(pub2, msg)
	require.NoError(t, err)
	sentDone <- true

	select {
	case <-listenDone:
		break
	case <-time.After(20 * time.Millisecond):
		t.Fatal("g2 not closing listening...")
	}
	select {
	case <-rcvDone:
		break
	case <-time.After(20 * time.Millisecond):
		t.Fatal("g1 not receiving anything")
	}
	require.Nil(t, g1.Stop())
	require.Nil(t, g2.Stop())

}

// FakeID returns a random ID with the given address.
func FakeID(addr string) (*key.Private, *key.Identity) {
	priv, id, err := key.NewPrivateIdentityWithAddr(addr, rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, id
}
