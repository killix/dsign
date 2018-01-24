package dkg

import (
	"sync"
	"testing"
	"time"

	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net"
	"github.com/nikkolasg/dsign/test"
	"github.com/nikkolasg/slog"
)

var encoder = net.NewSingleProtoEncoder(&Packet{})

type network struct {
	gw  net.Gateway
	dkg *Handler
}

func newDkgNetwork(gw net.Gateway, conf *Config) *network {
	n := &network{
		gw: gw,
	}
	gw.Start(n.Process)
	n.dkg = NewHandler(conf, n)
	return n
}

func (n *network) Send(id *key.Identity, p *Packet) error {
	buff, err := encoder.Marshal(p)
	if err != nil {
		return err
	}
	return n.gw.Send(id, buff)
}

func (n *network) Process(from *key.Identity, msg []byte) {
	packet, err := encoder.Unmarshal(msg)
	if err != nil {
		return
	}
	dkgPacket := packet.(*Packet)
	n.dkg.Process(from, dkgPacket)
}

func networks(keys []*key.Private, gws []net.Gateway, threshold int,
	shareCb func(Share), timeout time.Duration) []*network {
	list := test.ListFromPrivates(keys)
	nets := make([]*network, len(list), len(list))
	for i := range keys {
		conf := &Config{
			Private:       keys[i],
			List:          list,
			Threshold:     threshold,
			ShareCallback: shareCb,
			Timeout:       timeout,
		}
		nets[i] = newDkgNetwork(gws[i], conf)
	}
	return nets
}

func stopnetworks(nets []*network) {
	for i := range nets {
		if err := nets[i].gw.Stop(); err != nil {
			panic(err)
		}
	}
}

func TestDKG(t *testing.T) {
	n := 5
	thr := n/2 + 1
	privs, gws := test.Gateways(n)
	slog.Level = slog.LevelDebug
	defer func() { slog.Level = slog.LevelPrint }()

	// waits for receiving n shares
	var wg sync.WaitGroup
	wg.Add(n)
	callback := func(s Share) {
		wg.Done()
	}
	nets := networks(privs, gws, thr, callback, 100*time.Millisecond)
	defer stopnetworks(nets)

	nets[0].dkg.Start()
	wg.Wait()

}
