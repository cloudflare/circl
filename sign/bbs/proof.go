package bbs

import (
	"io"
	"slices"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/cryptobyte"
)

// Proof of knowledge of a BBS signature.
type Proof struct {
	mHat                     []scalar
	abar, bbar, d            g1
	eHat, r1Hat, r3Hat, chal scalar
}

// Size in bytes of a [Proof].
func (p *Proof) Size() uint                     { return 3*g1Size + (4+uint(len(p.mHat)))*scalarSize }
func (p *Proof) MarshalBinary() ([]byte, error) { return conv.MarshalBinaryLen(p, p.Size()) }
func (p *Proof) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(p, b) }
func (p *Proof) Marshal(b *cryptobyte.Builder) (e error) {
	b.AddBytes(p.abar.BytesCompressed())
	b.AddBytes(p.bbar.BytesCompressed())
	b.AddBytes(p.d.BytesCompressed())
	b.AddValue(&p.eHat)
	b.AddValue(&p.r1Hat)
	b.AddValue(&p.r3Hat)
	for i := uint(0); i < uint(len(p.mHat)); i++ {
		b.AddValue(&p.mHat[i])
	}
	b.AddValue(&p.chal)
	return nil
}

func (p *Proof) Unmarshal(s *cryptobyte.String) bool {
	var b [g1Size]byte
	ok := s.CopyBytes(b[:]) && p.abar.SetBytes(b[:]) == nil &&
		s.CopyBytes(b[:]) && p.bbar.SetBytes(b[:]) == nil &&
		s.CopyBytes(b[:]) && p.d.SetBytes(b[:]) == nil &&
		p.eHat.Unmarshal(s) &&
		p.r1Hat.Unmarshal(s) &&
		p.r3Hat.Unmarshal(s)
	if !ok {
		return false
	}

	var l []scalar
	var sc scalar
	for !s.Empty() {
		ok := sc.Unmarshal(s)
		if !ok {
			return false
		}
		l = append(l, sc)
	}

	if len(l) == 0 {
		return false
	}

	p.mHat = l[:len(l)-1]
	p.chal = l[len(l)-1]
	return true
}

type indexedScalar struct {
	bufScalar
	Index uint64
}

func proofInit(
	s suite,
	pub *PublicKey,
	sig *Signature,
	rndScalar []scalar,
	header []byte,
	messages []indexedScalar,
	concealed []indexedScalar,
) (res [5]g1, domain bufScalar) {
	Q1Gens := make([]g1, 1+len(messages))
	s.getQ1Gens(Q1Gens)
	domain = calcDomain(s, pub, Q1Gens, header)

	var B, t g1
	P1 := s.getP1()
	B.ScalarMult(&domain.scalar, &Q1Gens[0])
	B.Add(&B, &P1)
	generators := Q1Gens[1 : 1+len(messages)]
	for i := range messages {
		t.ScalarMult(
			&messages[i].bufScalar.scalar,
			&generators[messages[i].Index],
		)
		B.Add(&B, &t)
	}

	r3Tilde := &rndScalar[4]
	r1Tilde := &rndScalar[3]
	eTilde := &rndScalar[2]
	r2 := &rndScalar[1]
	r1 := &rndScalar[0]

	Abar := &res[0]
	Bbar := &res[1]
	D := &res[2]
	T1 := &res[3]
	T2 := &res[4]

	D.ScalarMult(r2, &B)

	var r scalar
	r.Mul(r1, r2)
	Abar.ScalarMult(&r, &sig.a)

	t.ScalarMult(&sig.e, Abar)
	t.Neg()
	Bbar.ScalarMult(r1, D)
	Bbar.Add(Bbar, &t)

	t.ScalarMult(r1Tilde, D)
	T1.ScalarMult(eTilde, Abar)
	T1.Add(T1, &t)

	T2.ScalarMult(r3Tilde, D)
	rndSc := rndScalar[5 : 5+len(concealed)]
	for i := range concealed {
		t.ScalarMult(&rndSc[i], &generators[concealed[i].Index])
		T2.Add(T2, &t)
	}

	return res, domain
}

func proofVerifyInit(
	s suite,
	pub *PublicKey,
	p *Proof,
	numGens uint64,
	header []byte,
	disclosed []indexedScalar,
) (res [5]g1, domain bufScalar) {
	Q1Gens := make([]g1, 1+numGens)
	s.getQ1Gens(Q1Gens)
	domain = calcDomain(s, pub, Q1Gens, header)

	res[0] = p.abar
	res[1] = p.bbar
	res[2] = p.d
	T1 := &res[3]
	T2 := &res[4]

	var t g1
	t.ScalarMult(&p.eHat, &p.abar)
	T1.ScalarMult(&p.chal, &p.bbar)
	T1.Add(T1, &t)
	t.ScalarMult(&p.r1Hat, &p.d)
	T1.Add(T1, &t)

	var Bv g1
	P1 := s.getP1()
	Bv.ScalarMult(&domain.scalar, &Q1Gens[0])
	Bv.Add(&Bv, &P1)

	T2.ScalarMult(&p.r3Hat, &p.d)

	var j, k uint
	maxJ := uint(len(disclosed))
	mHat := p.mHat
	maxK := uint(len(mHat))
	generators := Q1Gens[1:]
	for i := range generators {
		if j < maxJ && disclosed[j].Index == uint64(i) {
			t.ScalarMult(&disclosed[j].scalar, &generators[i])
			Bv.Add(&Bv, &t)
			j++
		} else if k < maxK {
			t.ScalarMult(&mHat[k], &generators[i])
			T2.Add(T2, &t)
			k++
		}
	}

	t.ScalarMult(&p.chal, &Bv)
	T2.Add(T2, &t)

	return res, domain
}

func proofFinalize(
	values *[5]g1,
	chal *scalar,
	eValue *scalar,
	rndScalar []scalar,
	concealed []indexedScalar,
) (p Proof) {
	p.abar = values[0]
	p.bbar = values[1]
	p.d = values[2]
	p.chal = *chal

	r3Tilde := &rndScalar[4]
	r1Tilde := &rndScalar[3]
	eTilde := &rndScalar[2]
	r2 := &rndScalar[1]
	r1 := &rndScalar[0]

	p.eHat.Mul(eValue, chal)
	p.eHat.Add(&p.eHat, eTilde)

	p.r1Hat.Mul(r1, chal)
	p.r1Hat.Sub(r1Tilde, &p.r1Hat)

	p.r3Hat.Inv(r2)
	p.r3Hat.Mul(&p.r3Hat, chal)
	p.r3Hat.Sub(r3Tilde, &p.r3Hat)

	mHat := make([]scalar, len(concealed))
	rndSc := rndScalar[5 : 5+len(concealed)]
	for i := range mHat {
		mHat[i].Mul(&concealed[i].scalar, chal)
		mHat[i].Add(&mHat[i], &rndSc[i])
	}

	p.mHat = mHat
	return p
}

// ProveOptions allows to specify a presentation header for proof generation.
type ProveOptions struct {
	PresentationHeader []byte
	SignOptions
}

type DisclosedMessage struct {
	Message Disclosed
	Index   uint64
}

// Prove creates a proof of knowledge of the signature, while disclosing a
// subset of messages.
// Messages must be in the same order as during signing.
// [ProveOptions] allows to specify a presentation header, the signature header,
// and the suite identifier.
func Prove(
	rnd io.Reader,
	pub *PublicKey,
	sig *Signature,
	messages []Msg,
	options ProveOptions,
) (*Proof, []DisclosedMessage, error) {
	s := options.ID.new()
	var numDisclosed, numConcealed uint
	for i := range messages {
		switch messages[i].(type) {
		case Disclosed:
			numDisclosed++
		case Concealed:
			numConcealed++
		}
	}

	rndScalars := make([]scalar, 5+numConcealed)
	err := randomScalars(rnd, rndScalars)
	if err != nil {
		return nil, nil, err
	}

	allMessages := make([]indexedScalar, numConcealed+numDisclosed)
	concealed := allMessages[0:numConcealed]
	disclosed := allMessages[numConcealed : numConcealed+numDisclosed]
	disclosedMessages := make([]DisclosedMessage, numDisclosed)

	h := s.newHasherScalar(s.MapDST())
	var j, k uint
	for i := range messages {
		scalar := indexedScalar{h.Hash(messages[i].get()), uint64(i)}
		switch mi := messages[i].(type) {
		case Disclosed:
			disclosedMessages[j] = DisclosedMessage{mi, uint64(i)}
			disclosed[j] = scalar
			j++
		case Concealed:
			concealed[k] = scalar
			k++
		}
	}

	res, domain := proofInit(s, pub, sig, rndScalars, options.Header,
		allMessages, concealed)
	ch := challenge(s, &res, &domain, disclosed, options.PresentationHeader)
	proof := proofFinalize(&res, &ch.scalar, &sig.e, rndScalars, concealed)
	return &proof, disclosedMessages, nil
}

// VerifyProof checks whether a proof of the signature and disclosed messages
// is valid.
// ProveOptions allows to specify a presentation header used during proof
// generation.
func VerifyProof(
	pub *PublicKey,
	proof *Proof,
	disclosedMessages []DisclosedMessage,
	options ProveOptions,
) bool {
	slices.SortFunc(disclosedMessages, func(a, b DisclosedMessage) int {
		if a.Index < b.Index {
			return -1
		} else if a.Index > b.Index {
			return 1
		}
		return 0
	})
	disclosedMsgsNoDup := slices.CompactFunc(disclosedMessages,
		func(a, b DisclosedMessage) bool { return a.Index == b.Index },
	)
	R := len(disclosedMsgsNoDup)
	// check for duplicates.
	if R != len(disclosedMessages) {
		return false
	}

	N := uint64(len(proof.mHat) + R)
	// check for out-of-range indexes.
	if R > 0 && disclosedMsgsNoDup[R-1].Index >= N {
		return false
	}

	s := options.ID.new()
	h := s.newHasherScalar(s.MapDST())
	disclosed := make([]indexedScalar, len(disclosedMsgsNoDup))
	for i := range disclosedMsgsNoDup {
		disclosed[i].Index = disclosedMsgsNoDup[i].Index
		disclosed[i].bufScalar = h.Hash(disclosedMsgsNoDup[i].Message)
	}

	res, domain := proofVerifyInit(s, pub, proof, N, options.Header, disclosed)
	ch := challenge(s, &res, &domain, disclosed, options.PresentationHeader)
	return ch.IsEqual(&proof.chal) == 1 && bls12381.ProdPairFrac(
		[]*g1{&proof.abar, &proof.bbar},
		[]*g2{&pub.key, bls12381.G2Generator()},
		[]int{1, -1}).IsIdentity()
}
