package key

import (
	"github.com/agl/ed25519/extra25519"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/encoding"
	"golang.org/x/crypto/ed25519"
)

// GroupConfig is the public configuration of a group using mulsigo. It is
// similar to a public pgp identity with a name, email and comment. It contains
// the additional public information on all the participants of the group.
type GroupConfig struct {
	Name    string
	Email   string
	Comment string

	// coefficients of the public polynomial
	Public []kyber.Point
	// list of node's identity participating
	Ids []Identity
	// threshold of the group
	T int

	PgpID     uint64
	PgpPublic string
}

type groupConfigToml struct {
	Name    string
	Email   string
	Comment string

	// coefficient of the public polynomial
	Public []string
	// list of node's identity participating
	Ids []identityToml
	// threshold of the group
	T int

	PgpID     string
	PgpPublic string
}

func (g *GroupConfig) toml() interface{} {
	publics := make([]string, len(g.Public))
	for i, p := range g.Public {
		s, err := encoding.PointToString64(Group, p)
		if err != nil {
			return err
		}
		publics[i] = s
	}

	ids := make([]identityToml, len(g.Ids))
	for i, id := range g.Ids {
		itoml := id.Toml().(*identityToml)
		ids[i] = *itoml
	}

	return &groupConfigToml{
		Name:      g.Name,
		Email:     g.Email,
		Comment:   g.Comment,
		Public:    publics,
		Ids:       ids,
		T:         g.T,
		PgpPublic: g.PgpPublic,
	}
}

func ed25519PrivateToCurve25519(p *ed25519.PrivateKey) [32]byte {
	var buff [64]byte
	copy(buff[:], *p)
	var curvePriv [32]byte

	extra25519.PrivateKeyToCurve25519(&curvePriv, &buff)
	return curvePriv
}

func ed25519PublicToCurve25519(p *ed25519.PublicKey) ([32]byte, bool) {
	var buff [32]byte
	copy(buff[:], *p)
	var curvePub [32]byte

	ret := extra25519.PublicKeyToCurve25519(&curvePub, &buff)
	return curvePub, ret
}
