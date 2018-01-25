package key

import "github.com/dedis/kyber"

// IdentitiesToPoints returns a list of kyber.Point from a list of Identity
func IdentitiesToPoints(list []*Identity) []kyber.Point {
	n := len(list)
	p := make([]kyber.Point, n, n)
	for i := range list {
		p[i] = list[i].Point()
	}
	return p
}
