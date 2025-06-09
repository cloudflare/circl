package bbs

import (
	"crypto"
	"io"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/cryptobyte"
)

type Signature struct {
	a g1
	e scalar
}

func (s *Signature) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinaryLen(s, SignatureSize)
}

func (s *Signature) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(s, b)
}

func (s *Signature) Marshal(b *cryptobyte.Builder) (e error) {
	b.AddBytes(s.a.BytesCompressed())
	b.AddValue(&s.e)
	return
}

func (s *Signature) Unmarshal(st *cryptobyte.String) bool {
	var b [g1Size]byte
	return st.CopyBytes(b[:]) && s.a.SetBytes(b[:]) == nil && s.e.Unmarshal(st)
}

// SignOptions used for configuration of signing.
type SignOptions struct {
	Header []byte  // Header used to bind public information to the signature.
	ID     SuiteID // ID determines the suite of algorithms.
}

// HashFunc always returns the zero value.
func (SignOptions) HashFunc() (h crypto.Hash) { return }

// Sign produces a signature over one message.
// Use the [Sign] function for signing multiple messages.
//
// The io.Reader is ignored because signatures are deterministic.
// Passing a [SignOptions] struct allows to specify a signature header and
// the suite identifier.
// When nil is passed as options, the zero value of [SignOptions] is used.
// If successful, it returns the serialization of the signature.
func (k *PrivateKey) Sign(
	rnd io.Reader, message []byte, options crypto.SignerOpts,
) ([]byte, error) {
	var op SignOptions
	if options != nil {
		cOpts, ok := options.(SignOptions)
		if ok {
			op = cOpts
		} else {
			return nil, ErrInvalidOpts
		}
	}

	s := Sign(k, [][]byte{message}, op)
	return s.MarshalBinary()
}

// Sign produces a signature over multiple messages.
//
// Sign is sensitive to the order of input messages.
// [SignOptions] allows to specify a signature header and the suite identifier.
func Sign(
	key *PrivateKey, messages [][]byte, options SignOptions,
) (sig Signature) {
	s := options.ID.new()
	key.calcPublicKey()
	bLen := scalarSize * (2 + len(messages))
	b := cryptobyte.NewFixedBuilder(make([]byte, 0, bLen))
	b.AddValue(key)
	B := calculateB(s, key.pub, messages, options.Header, b)
	e := s.hashToScalar(b.BytesOrPanic(), s.HashToScalarDST())
	if e.scalar.IsEqual(&key.key.scalar) == 1 {
		panic(ErrSignature)
	}

	var skE scalar
	skE.Add(&key.key.scalar, &e.scalar)
	skE.Inv(&skE)
	sig.a.ScalarMult(&skE, &B)
	sig.e = e.scalar
	return sig
}

// Verify checks whether the signature over the messages is valid.
// Messages must be in the same order as during signing.
// [SignOptions] allows to specify a signature header and the suite identifier.
func Verify(
	pub *PublicKey, sig *Signature, messages [][]byte, options SignOptions,
) bool {
	var t g1
	B := calculateB(options.ID.new(), pub, messages, options.Header, nil)
	B.Neg()
	t.ScalarMult(&sig.e, &sig.a)
	t.Add(&t, &B)

	// (A,W)*(eA-B,BP2)
	return bls12381.ProdPairFrac(
		[]*g1{&sig.a, &t},
		[]*g2{&pub.key, bls12381.G2Generator()},
		[]int{1, 1},
	).IsIdentity()
}

func calculateB(
	s suite,
	pub *PublicKey,
	messages [][]byte,
	header []byte,
	b *cryptobyte.Builder,
) (B g1) {
	Q1Gens := make([]g1, 1+len(messages))
	s.getQ1Gens(Q1Gens)
	domain := calcDomain(s, pub, Q1Gens, header)

	P1 := s.getP1()
	B.ScalarMult(&domain.scalar, &Q1Gens[0])
	B.Add(&B, &P1)

	generators := Q1Gens[1 : 1+len(messages)]
	H := s.newHasherScalar(s.MapDST())
	var t g1
	for i := range messages {
		mi := H.Hash(messages[i])
		t.ScalarMult(&mi.scalar, &generators[i])
		B.Add(&B, &t)

		if b != nil {
			b.AddValue(&mi)
		}
	}

	if b != nil {
		b.AddValue(&domain)
	}

	return B
}
