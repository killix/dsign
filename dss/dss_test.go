package dss

import (
	"fmt"
	"testing"

	"github.com/alecthomas/assert"
	"github.com/dedis/kyber"
	dkgg "github.com/dedis/kyber/share/dkg/pedersen"
	"github.com/dedis/kyber/sign/schnorr"
	"github.com/nikkolasg/dsign/dkg"
	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net"
	"github.com/nikkolasg/dsign/test"
	"github.com/nikkolasg/slog"
	"github.com/stretchr/testify/require"
)

var encoder = net.NewSingleProtoEncoder(&Packet{})

type network struct {
	gw  net.Gateway
	dss *Handler
}

func newDssNetwork(gw net.Gateway, priv *key.Private, conf *Config) *network {
	n := &network{
		gw: gw,
	}
	gw.Start(n.Process)
	n.dss = NewHandler(priv, conf, n)
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
	n.dss.Process(from, dkgPacket)
}

func networks(keys []*key.Private, gws []net.Gateway, list []*key.Identity,
	longterms, randoms []*dkg.Share,
	threshold int, message []byte) []*network {
	n := len(keys)
	nets := make([]*network, n, n)
	for i := range keys {
		dkgConf := &dkg.Config{
			List:      list,
			Threshold: threshold,
		}
		dssConf := &Config{
			Config:   dkgConf,
			Longterm: longterms[i],
			Random:   randoms[i],
			Message:  message,
			//  TIMEOUT TODO
		}
		nets[i] = newDssNetwork(gws[i], keys[i], dssConf)
	}
	return nets
}

func stopnetworks(nets []*network) {
	for i := range nets {
		fmt.Printf("Closing gw %p\n", &nets[i].gw)
		if err := nets[i].gw.Stop(); err != nil {
			panic(err)
		}
	}
}

func TestDSS(t *testing.T) {
	n := 5
	thr := n/2 + 1
	message := []byte("Hello World")
	privs, gws := test.Gateways(n)
	list := test.ListFromPrivates(privs)
	points := key.IdentitiesToPoints(list)
	longterms := genShares(privs, points, thr, t)
	randoms := genShares(privs, points, thr, t)
	nets := networks(privs, gws, list, longterms, randoms, thr, message)
	defer stopnetworks(nets)

	slog.Level = slog.LevelDebug
	defer func() { slog.Level = slog.LevelPrint }()

	nets[0].dss.Start()
	sig := <-nets[0].dss.WaitSignature()
	require.Nil(t, schnorr.Verify(key.Curve, longterms[0].Public(), message, sig))
	fmt.Println("DONE")
}

func genShares(keys []*key.Private, points []kyber.Point, threshold int, t *testing.T) []*dkg.Share {
	n := len(keys)
	dkgs := make([]*dkgg.DistKeyGenerator, n, n)
	for i := 0; i < n; i++ {
		dkg, err := dkgg.NewDistKeyGenerator(key.Curve, keys[i].Scalar(), points, threshold)
		require.Nil(t, err)
		dkgs[i] = dkg
	}
	// 1. broadcast deals
	resps := make([]*dkgg.Response, 0, n)
	for _, gen := range dkgs {
		deals, err := gen.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			require.Nil(t, err)
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for i, gen := range dkgs {
			// Ignore messages about ourselves
			if resp.Response.Index == uint32(i) {
				continue
			}
			j, err := gen.ProcessResponse(resp)
			require.Nil(t, err)
			require.Nil(t, j)
		}
	}

	// 3. Make sure every dkg is certified
	for _, dkg := range dkgs {
		assert.True(t, dkg.Certified())
	}

	// 4. collect shares
	dkss := make([]*dkg.Share, n)
	for i, gen := range dkgs {
		dks, err := gen.DistKeyShare()
		require.Nil(t, err)
		require.NotNil(t, dks)
		sh := dkg.Share(*dks)
		dkss[i] = &sh
	}
	return dkss
}
