package bbs

import (
	"io"
	"math/big"

	"github.com/cloudflare/circl/expander"
	"golang.org/x/crypto/cryptobyte"
)

func calcDomain(
	s suite,
	pub *PublicKey,
	Q1Gens []g1,
	header []byte,
) bufScalar {
	apiID := s.apiID()
	bLen := PublicKeySize + 16 + len(Q1Gens)*g1Size + len(apiID) + len(header)
	b := cryptobyte.NewFixedBuilder(make([]byte, 0, bLen))
	b.AddValue(pub)
	b.AddUint64(uint64(len(Q1Gens) - 1))
	for i := range Q1Gens {
		b.AddBytes(Q1Gens[i].BytesCompressed())
	}

	b.AddBytes(apiID)
	b.AddUint64(uint64(len(header)))
	b.AddBytes(header)
	return s.hashToScalar(b.BytesOrPanic(), s.HashToScalarDST())
}

func challenge(
	s suite,
	values *[5]g1,
	domain *bufScalar,
	disclosed []indexedScalar,
	presentationHeader []byte,
) bufScalar {
	bLen := 8 + len(disclosed)*(8+scalarSize) + len(values)*g1Size +
		scalarSize + 8 + len(presentationHeader)
	b := cryptobyte.NewFixedBuilder(make([]byte, 0, bLen))
	b.AddUint64(uint64(len(disclosed)))
	for i := range disclosed {
		b.AddUint64(disclosed[i].Index)
		b.AddValue(&disclosed[i])
	}

	for i := range values {
		b.AddBytes(values[i].BytesCompressed())
	}

	b.AddValue(domain)
	b.AddUint64(uint64(len(presentationHeader)))
	b.AddBytes(presentationHeader)
	return s.hashToScalar(b.BytesOrPanic(), s.HashToScalarDST())
}

func randomScalars(rnd io.Reader, out []scalar) error {
	for i := range out {
		err := out[i].Random(rnd)
		if err != nil {
			return err
		}
	}
	return nil
}

type hasherScalar struct {
	exp  expander.Expander
	r, u big.Int
}

func (h *hasherScalar) Hash(msg []byte) (s bufScalar) {
	bytes := h.exp.Expand(msg, expandLen)
	h.u.SetBytes(bytes)
	h.u.Mod(&h.u, &h.r)
	h.u.FillBytes(s.encoded[:])
	err := s.scalar.UnmarshalBinary(s.encoded[:])
	if err != nil {
		panic(err)
	}

	return s
}

type bufScalar struct {
	scalar
	encoded [scalarSize]byte
}

func (s *bufScalar) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(s.encoded[:])
	return nil
}

func (s *bufScalar) Unmarshal(str *cryptobyte.String) bool {
	var b [scalarSize]byte
	ok := str.CopyBytes(b[:]) && s.scalar.UnmarshalBinary(b[:]) == nil
	if ok {
		s.encoded = b
	}
	return ok
}
