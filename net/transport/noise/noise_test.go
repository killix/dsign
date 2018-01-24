package net

import (
	"testing"

	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net/transport"
	"github.com/nikkolasg/dsign/net/transport/internal"
	"github.com/nikkolasg/dsign/test"
)

type noiseFactory struct{}

func (nf *noiseFactory) NewTransports(n int) ([]*key.Private, []transport.Transport) {
	trs := make([]transport.Transport, n, n)
	ids := test.GenerateIDs(8000, n)
	list := make([]*key.Identity, n, n)
	for i := range ids {
		list[i] = ids[i].Public
	}
	for i := range trs {
		trs[i] = NewTCPNoiseTransport(ids[i], list)
	}
	return ids, trs
}

func TestNoiseGeneric(t *testing.T) {
	internal.TestTransport(t, new(noiseFactory))
}
