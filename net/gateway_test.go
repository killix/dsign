package net_test

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net"
	"github.com/nikkolasg/dsign/net/transport/tcp"
	"github.com/stretchr/testify/require"
)

func TestGateway(t *testing.T) {
	t.Skip()
	_, pub1 := fakeID("127.0.0.1:8000")
	tr1 := tcp.NewTCPTransport(pub1)
	g1 := net.NewGateway(tr1)

	_, pub2 := fakeID("127.0.0.1:8001")
	tr2 := tcp.NewTCPTransport(pub2)
	g2 := net.NewGateway(tr2)

	listenDone := make(chan bool)
	handler := func(from *key.Identity, msg *net.ClientMessage) {
		// XXX from is nil for tcp connections only. need to do noise XXX
		require.Nil(t, g2.Send(from, msg))
		require.Nil(t, g2.Stop())
		listenDone <- true
	}

	require.Nil(t, g2.Start(handler))
	time.Sleep(10 * time.Millisecond)
	msg := &net.ClientMessage{}
	err := g1.Send(pub2, msg)
	if err != nil {
		fmt.Println(err.Error())
		require.Nil(t, err)
	}
	require.Nil(t, g1.Stop())
	select {
	case <-listenDone:
		return
	case <-time.After(20 * time.Millisecond):
		t.Fatal("g2 not closing listening...")
	}
}

func fakeID(addr string) (*key.Private, *key.Identity) {
	priv, id, err := key.NewPrivateIdentityWithAddr(addr, rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, id
}
