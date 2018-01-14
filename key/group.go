package key

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/encoding"
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
		s, err := encoding.PointToStringHex(Group, p)
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
