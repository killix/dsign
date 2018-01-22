package net

import (
	"fmt"

	"github.com/nikkolasg/NoiseGo/noise"
	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net/transport"
	"github.com/nikkolasg/dsign/net/transport/tcp"
)

type noiseTransport struct {
	kp     *noise.KeyPair
	lookup map[string]*key.Identity
	tr     transport.Transport
}

// newNoiseTransport returns a Transport that encrypts connection from the
// underlying transport using the noise framework.
// XXX So far non-exported because it may be unsafe to use noise with another
// non-controllable transport...
func newNoiseTransport(priv *key.Private, list []*key.Identity, tr transport.Transport) transport.Transport {
	kp := &noise.KeyPair{
		PrivateKey: priv.PrivateCurve25519(),
		PublicKey:  priv.PublicCurve25519(),
	}
	lookup := make(map[string]*key.Identity, len(list))
	for i := range list {
		c := list[i].PublicCurve25519()
		s := string(c[:])
		lookup[s] = list[i]
	}
	return &noiseTransport{
		kp:     kp,
		lookup: lookup,
		tr:     tr,
	}
}

// NewTCPNoiseTransport returns a Transport that uses encrypted TCP
// communication using the noise framework.
func NewTCPNoiseTransport(priv *key.Private, list []*key.Identity) transport.Transport {
	return newNoiseTransport(priv, list, tcp.NewTCPTransport(priv.Public))
}

func (nt *noiseTransport) Dial(id *key.Identity) (transport.Conn, error) {
	conn, err := nt.tr.Dial(id)
	if err != nil {
		return nil, err
	}
	remoteBuff := id.PublicCurve25519()
	conf := &noise.Config{
		HandshakePattern: noise.Noise_XK,
		KeyPair:          nt.kp,
		RemoteKey:        remoteBuff[:],
	}
	noiseConn := noise.Client(conn, conf)
	return noiseConn, noiseConn.Handshake()
}

func (nt *noiseTransport) Listen(h transport.Handler) error {
	localHandler := h
	var noiseHandler transport.Handler
	noiseHandler = func(id *key.Identity, conn transport.Conn) {
		conf := &noise.Config{
			HandshakePattern: noise.Noise_XK,
			KeyPair:          nt.kp,
			PublicKeyVerifier: func(pub, proof []byte) bool {
				return nt.isIncluded(pub)
			},
		}
		noiseConn := noise.Server(conn, conf)
		if err := noiseConn.Handshake(); err != nil {
			fmt.Println("XXX Log or pass up the error?")
			return
		}
		static, err := noiseConn.StaticKey()
		if err != nil {
			fmt.Println("XXX Log or pass up the error?")
			return
		}
		identity, present := nt.lookup[string(static)]
		if !present {
			panic("this is bad. Run. ")
		}
		localHandler(identity, noiseConn)
	}
	return nt.tr.Listen(transport.Handler(noiseHandler))
}

func (nt *noiseTransport) Close() error {
	return nt.tr.Close()
}

// insIncluded checks in constant time if the given public identity is known in
// the list of peers or not.
func (nt *noiseTransport) isIncluded(pub []byte) bool {
	_, present := nt.lookup[string(pub)]
	return present
}
