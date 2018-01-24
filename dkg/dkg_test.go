package dkg

import (
	"sync"
	"testing"

	"github.com/nikkolasg/slog"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/kyber.v0/share/dkg"
)

func TestDKG(t *testing.T) {
	n := 5
	//thr := n/2 + 1
	privs, ids := BatchPrivateIdentity(n)
	slog.Level = slog.LevelDebug
	defer func() { slog.Level = slog.LevelPrint }()

	//routers := BatchRouters(ids)
	relay, routers := BatchRelayRouters(privs, ids)
	defer relay.Stop()

	dkgs := BatchDKGs(privs, ids, routers)
	dkss := make([]*dkg.DistKeyShare, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(j int) {
			dks, err := dkgs[j].Run()
			require.Nil(t, err)
			dkss[j] = dks
			wg.Done()
		}(i)
	}

	wg.Wait()
}
