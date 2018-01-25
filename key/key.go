// Package key defines the different cryptographic materials used
// by dsign.
package key

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"

	"github.com/BurntSushi/toml"
	"github.com/agl/ed25519/extra25519"
	kyber "github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
)

// Curve is statically defined so it is compatible with EdDSA
// ed25519 implementations
var Curve = edwards25519.NewBlakeSHA256Ed25519()

// Private contains the private ed25519 key (seed) and the
// related private key
type Private struct {
	seed   *ed25519.PrivateKey
	Public *Identity
}

// Scalar returns a kyber.Scalar representation of the Private key.
func (p *Private) Scalar() kyber.Scalar {
	h := sha512.New()
	h.Write((*p.seed)[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	s := Curve.Scalar()
	if err := s.UnmarshalBinary(digest[:32]); err != nil {
		panic(err)
	}
	return s
}

// PrivateCurve25519 returns a private key typed to be compatible
// with what most ed25519 libraries expect.
func (p *Private) PrivateCurve25519() [32]byte {
	return ed25519PrivateToCurve25519(p.seed)
}

// PublicCurve25519 returns a public key typed to be compatible
// with what most ed25519 libraries expect.
func (p *Private) PublicCurve25519() [32]byte {
	priv := p.PrivateCurve25519()
	var pubCurve [32]byte
	curve25519.ScalarBaseMult(&pubCurve, &priv)
	return pubCurve
}

// NewPrivateIdentity creates a new private / public key pair given
// from the given reader = randomness source. It is highly
// recommended to use crypto/rand.
func NewPrivateIdentity(r io.Reader) (*Private, *Identity, error) {
	return NewPrivateIdentityWithAddr("", r)
}

// NewPrivateIdentityWithAddr is similar to NewPrivateIdentity but
// specify an address within the newly created private key.
func NewPrivateIdentityWithAddr(addr string, r io.Reader) (*Private, *Identity, error) {
	pub, privEd, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, err
	}
	id := &Identity{
		Key:     pub,
		Address: addr,
	}
	priv := &Private{seed: &privEd, Public: id}

	id.selfsign(priv, r)
	return priv, id, nil
}

// Identity contains all public information that can be used to
// identity a participant.
type Identity struct {
	// ed25519 public key
	Key []byte
	// self signature
	Signature []byte
	// ID represents a condensed version of this Identity. Specifically, it is
	// the hex representation of the hash of the signature using sha256.
	ID string
	// reachable - usually empty if using a relay but if provided, will enable
	// one to make direct connection between a pair of peers.
	Address string
}

// selfsign marshals the identity's public key, and the address if present, and
// then signs the resulting buffer. The signature can be accessed through the
// Signature field of the Identity. It is a regular Eddsa signature.
func (i *Identity) selfsign(p *Private, r io.Reader) {
	var buff bytes.Buffer
	buff.Write(i.Key)
	if i.Address != "" {
		buff.Write([]byte(i.Address))
	}
	i.Signature = ed25519.Sign(*p.seed, buff.Bytes())
	b := sha256.Sum256(i.Signature)
	i.ID = hex.EncodeToString(b[:])
}

// PublicCurve25519 returns a ed25519 public key.
func (i *Identity) PublicCurve25519() [32]byte {
	var pubEd25519 [32]byte
	var pubCurve [32]byte
	copy(pubEd25519[:], i.Key)
	ret := extra25519.PublicKeyToCurve25519(&pubCurve, &pubEd25519)
	if !ret {
		panic("corrupted private key? can't convert to curve25519")
	}
	return pubCurve
}

type privateToml struct {
	Seed string
}

// Toml returns a TOML-able struct containing the base64
// encoded private key
func (p *Private) Toml() interface{} {
	seedStr := base64.StdEncoding.EncodeToString(*p.seed)

	return &privateToml{seedStr}
}

// FromToml reads the given input string to parse the private
// key.
func (p *Private) FromToml(f string) error {
	pt := &privateToml{}
	_, err := toml.Decode(f, pt)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(pt.Seed)
	seedEd25519 := ed25519.PrivateKey(seed)
	p.seed = &seedEd25519
	return err
}

type identityToml struct {
	Name      string
	Key       string
	CreatedAt int64
	Signature string
	Address   string
}

// Toml returns a TOML-able struct containing base64 public key
// encoded and the signature.
func (i *Identity) Toml() interface{} {
	publicStr := base64.StdEncoding.EncodeToString(i.Key)
	sigStr := base64.StdEncoding.EncodeToString(i.Signature)
	return &identityToml{
		Key:       publicStr,
		Signature: sigStr,
		Address:   i.Address,
	}
}

// FromToml reads the given string to parse the Identity.
func (i *Identity) FromToml(f string) error {
	it := &identityToml{}
	_, err := toml.Decode(f, it)
	if err != nil {
		return err
	}
	public, err := base64.StdEncoding.DecodeString(it.Key)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(it.Signature)
	if err != nil {
		return err
	}
	i.Key = public
	i.Address = it.Address
	i.Signature = signature
	return nil
}

// Point returns a kyber.Point of the ed25519 public key inside i.
func (i *Identity) Point() kyber.Point {
	p := Curve.Point()
	if err := p.UnmarshalBinary(i.Key); err != nil {
		panic(err)
	}
	return p
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
