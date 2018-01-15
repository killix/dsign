package net

import (
	"crypto/rand"
	"testing"

	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net/transport/tcp"
)

func TestGateway(t *testing.T) {
	priv1, pub1 := fakeId("127.0.0.1:8000")
	tr1 := tcp.NewTcpTransport()

	priv2, pub2 := fakeId("127.0.0.1:8001")
	tr2 := tcp.NewTcpTransport()

}

func fakeId(addr string) (*key.Private, *key.Identity) {
	priv, id, err := key.NewPrivateIdentityWithAddr(addr, rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, id
}
