package net_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net"
	"github.com/nikkolasg/dsign/net/transport/tcp"
	"github.com/stretchr/testify/require"
)

func TestGateway(t *testing.T) {
	_, pub1 := fakeID("127.0.0.1:8000")
	tr1 := tcp.NewTCPTransport(pub1)
	g1 := net.NewGateway(tr1)

	_, pub2 := fakeID("127.0.0.1:8001")
	tr2 := tcp.NewTCPTransport(pub2)
	g2 := net.NewGateway(tr2)

	listenDone := make(chan bool)
	rcvDone := make(chan bool)
	handler2 := func(from *key.Identity, msg []byte) {
		// XXX from is nil for tcp connections only. need to do noise XXX
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
	if err != nil {
		//fmt.Println(err.Error())
		require.Nil(t, err)
	}
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

func fakeID(addr string) (*key.Private, *key.Identity) {
	priv, id, err := key.NewPrivateIdentityWithAddr(addr, rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, id
}
