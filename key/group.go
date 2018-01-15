package key

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/encoding"
)

// GroupIdentity is the identity of a group created with dsign. It is
// similar to a public pgp identity with a name, email and comment. It contains
// the additional public information on all the participants of the group.
type GroupIdentity struct {
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

type groupToml struct {
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

func (g *GroupIdentity) toml() interface{} {
	publics := make([]string, len(g.Public))
	for i, p := range g.Public {
		s, err := encoding.PointToStringHex(Curve, p)
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

	return &groupToml{
		Name:      g.Name,
		Email:     g.Email,
		Comment:   g.Comment,
		Public:    publics,
		Ids:       ids,
		T:         g.T,
		PgpPublic: g.PgpPublic,
	}
}
