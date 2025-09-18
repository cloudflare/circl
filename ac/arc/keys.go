package arc

import (
	"crypto"
	"crypto/rand"
	"io"
	"slices"

	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/cryptobyte"
)

type PrivateKey struct {
	x0, x1, x2, x0Blinding scalar
	pub                    *PublicKey
	ID                     SuiteID
}

func (k PrivateKey) String() string {
	return printAny(k.x0, k.x1, k.x2, k.x0Blinding)
}

func (k *PrivateKey) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(k, b)
}

func (k *PrivateKey) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(k)
}

func (k *PrivateKey) Marshal(b *cryptobyte.Builder) error {
	return conv.MarshalSlice(b, k.x0, k.x1, k.x2, k.x0Blinding)
}

func (k *PrivateKey) Unmarshal(s *cryptobyte.String) bool {
	suite := k.ID.getSuite()
	suite.initScalar(&k.x0, &k.x1, &k.x2, &k.x0Blinding)
	return conv.UnmarshalSlice(s, k.x0, k.x1, k.x2, k.x0Blinding)
}

func (k *PrivateKey) Equal(priv crypto.PrivateKey) bool {
	x, ok := priv.(*PrivateKey)
	return ok && k.ID == x.ID &&
		slices.EqualFunc(
			[]scalar{k.x0, k.x1, k.x2, k.x0Blinding},
			[]scalar{x.x0, x.x1, x.x2, x.x0Blinding},
			scalar.IsEqual)
}

func (k *PrivateKey) Public() crypto.PublicKey { return k.PublicKey() }
func (k *PrivateKey) PublicKey() PublicKey {
	if k.pub == nil {
		s := k.ID.getSuite()
		x0 := s.newElement()
		x1 := s.newElement()
		x2 := s.newElement()
		x0.Add(x0.MulGen(k.x0), x1.Mul(s.genH, k.x0Blinding))
		x1.Mul(s.genH, k.x1)
		x2.Mul(s.genH, k.x2)
		k.pub = &PublicKey{
			ID: k.ID,
			x0: x0,
			x1: x1,
			x2: x2,
		}
	}

	return *k.pub
}

type PublicKey struct {
	x0, x1, x2 elt
	ID         SuiteID
}

func (k PublicKey) String() string {
	return printAny(k.x0, k.x1, k.x2)
}

func (k *PublicKey) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(k, b)
}

func (k *PublicKey) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(k)
}

func (k *PublicKey) Marshal(b *cryptobyte.Builder) error {
	return conv.MarshalSlice(b, eltCom{k.x0}, eltCom{k.x1}, eltCom{k.x2})
}

func (k *PublicKey) Unmarshal(s *cryptobyte.String) bool {
	suite := k.ID.getSuite()
	suite.initElt(&k.x0, &k.x1, &k.x2)
	return conv.UnmarshalSlice(s, eltCom{k.x0}, eltCom{k.x1}, eltCom{k.x2})
}

func (k *PublicKey) Equal(pub crypto.PublicKey) bool {
	x, ok := pub.(*PublicKey)
	return ok && k.ID == x.ID && slices.EqualFunc(
		[]elt{k.x0, k.x1, k.x2},
		[]elt{x.x0, x.x1, x.x2},
		elt.IsEqual)
}

func KeyGen(rnd io.Reader, id SuiteID) PrivateKey {
	if rnd == nil {
		rnd = rand.Reader
	}

	s := id.getSuite()
	return PrivateKey{
		ID:         id,
		x0:         s.randomScalar(rnd),
		x1:         s.randomScalar(rnd),
		x2:         s.randomScalar(rnd),
		x0Blinding: s.randomScalar(rnd),
	}
}
