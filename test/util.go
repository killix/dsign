package test

import (
	"crypto/rand"
	"strconv"

	"github.com/nikkolasg/dsign/key"
)

// FakeID returns a random ID with the given address.
func FakeID(addr string) (*key.Private, *key.Identity) {
	priv, id, err := key.NewPrivateIdentityWithAddr(addr, rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, id
}

// Addresses returns a list of TCP localhost addresses starting from the given
// port= start.
func Addresses(start, n int) []string {
	addrs := make([]string, n, n)
	for i := 0; i < n; i++ {
		addrs[i] = "127.0.0.1:" + strconv.Itoa(start+i)
	}
	return addrs
}

// GenerateIDs returns n private keys with the start address given to Addresses
func GenerateIDs(start, n int) []*key.Private {
	keys := make([]*key.Private, n)
	addrs := Addresses(start, n)
	for i := range addrs {
		priv, _ := FakeID(addrs[i])
		keys[i] = priv
	}
	return keys
}
