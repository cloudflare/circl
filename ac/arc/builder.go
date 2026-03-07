package arc

import (
	"crypto/rand"
	"io"
	"slices"

	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/cryptobyte"
)

type proof struct {
	chal scalar
	resp []scalar
}

func (p proof) String() string { return printAny(p.chal, p.resp) }

func (p *proof) init(s *suite, num uint) {
	p.chal = s.newScalar()
	p.resp = make([]scalar, num)
	for i := range num {
		p.resp[i] = s.newScalar()
	}
}

func (p proof) IsEqual(x proof) bool {
	return slices.EqualFunc(
		append([]scalar{p.chal}, p.resp...),
		append([]scalar{x.chal}, x.resp...),
		scalar.IsEqual)
}

func (p proof) Marshal(b *cryptobyte.Builder) error {
	v := make([]cryptobyte.MarshalingValue, 0, 1+len(p.resp))
	v = append(v, p.chal)
	for i := range p.resp {
		v = append(v, p.resp[i])
	}

	return conv.MarshalSlice(b, v...)
}

func (p proof) Unmarshal(s *cryptobyte.String) bool {
	v := make([]conv.UnmarshalingValue, 0, 1+len(p.resp))
	v = append(v, p.chal)
	for i := range p.resp {
		v = append(v, p.resp[i])
	}

	return conv.UnmarshalSlice(s, v...)
}

type (
	scalarIndex uint
	elemIndex   uint
	mul         struct {
		s scalarIndex
		e elemIndex
	}
	constraint struct {
		c []mul
		z elemIndex
	}
)

type builder struct {
	*suite
	ctx          string
	scalarLabels [][]byte
	elemLabels   [][]byte
	elems        []elt
	cons         []constraint
}

func (b *builder) AppendScalar(label []byte) scalarIndex {
	b.scalarLabels = append(b.scalarLabels, label)
	return scalarIndex(len(b.scalarLabels) - 1)
}

func (b *builder) AppendElement(label []byte, e elt) elemIndex {
	b.elems = append(b.elems, e)
	b.elemLabels = append(b.elemLabels, label)
	return elemIndex(len(b.elems) - 1)
}

func (b *builder) Constrain(z elemIndex, m ...mul) {
	b.cons = append(b.cons, constraint{m, z})
}

func (b *builder) calcChallenge(elems ...[]elt) scalar {
	length := 0
	for i := range elems {
		length += len(elems[i])
	}

	sizeElement := b.suite.sizeElement()
	length *= 2 + int(sizeElement)
	cb := cryptobyte.NewFixedBuilder(make([]byte, 0, length))
	for _, list := range elems {
		for i := range list {
			cb.AddUint16(uint16(sizeElement))
			_ = eltCom{list[i]}.Marshal(cb)
		}
	}

	return b.suite.hashToScalar(cb.BytesOrPanic(), b.suite.chalContext(b.ctx))
}

type prover struct {
	builder
	scalars []scalar
}

func newProver(id SuiteID, ctx string) (p prover) {
	p.builder = builder{suite: id.getSuite(), ctx: ctx}
	return
}

func (c *prover) AppendScalar(label []byte, s scalar) scalarIndex {
	c.scalars = append(c.scalars, s)
	return c.builder.AppendScalar(label)
}

func (c *prover) Prove(rnd io.Reader) (p proof) {
	if rnd == nil {
		rnd = rand.Reader
	}

	blindings := make([]scalar, len(c.scalars))
	for i := range blindings {
		blindings[i] = c.suite.randomScalar(rnd)
	}

	blindedElts := make([]elt, len(c.cons))
	t := c.suite.newElement()
	for i := range c.cons {
		index := c.cons[i].z
		if index > elemIndex(len(c.elems)) {
			panic(ErrInvalidIndex)
		}

		sum := c.suite.newElement()
		for j := range c.cons[i].c {
			scalarIdx := c.cons[i].c[j].s
			elemIdx := c.cons[i].c[j].e

			if scalarIdx > scalarIndex(len(blindings)) {
				panic(ErrInvalidIndex)
			}

			if elemIdx > elemIndex(len(c.elems)) {
				panic(ErrInvalidIndex)
			}

			t.Mul(c.elems[elemIdx], blindings[scalarIdx])
			sum.Add(sum, t)
		}

		blindedElts[i] = sum
	}

	p.init(c.suite, uint(len(c.scalars)))
	p.chal = c.calcChallenge(c.elems, blindedElts)
	for i := range p.resp {
		p.resp[i].Sub(blindings[i], p.resp[i].Mul(p.chal, c.scalars[i]))
	}

	clear(blindings)
	return p
}

type verifier struct{ builder }

func newVerifier(id SuiteID, ctx string) (v verifier) {
	v.builder = builder{suite: id.getSuite(), ctx: ctx}
	return
}

func (v *verifier) Verify(p *proof) bool {
	if len(v.elems) != len(v.elemLabels) {
		return false
	}

	blindedElts := make([]elt, len(v.cons))
	t := v.suite.newElement()
	for i := range v.cons {
		index := v.cons[i].z
		if index > elemIndex(len(v.elems)) {
			panic(ErrInvalidIndex)
		}

		sum := v.suite.newElement()
		sum.Mul(v.elems[index], p.chal)
		for j := range v.cons[i].c {
			scalarIdx := v.cons[i].c[j].s
			elemIdx := v.cons[i].c[j].e

			if scalarIdx > scalarIndex(len(p.resp)) {
				panic(ErrInvalidIndex)
			}

			if elemIdx > elemIndex(len(v.elems)) {
				panic(ErrInvalidIndex)
			}

			t.Mul(v.elems[elemIdx], p.resp[scalarIdx])
			sum.Add(sum, t)
		}

		blindedElts[i] = sum
	}

	chal := v.calcChallenge(v.elems, blindedElts)
	return p.chal.IsEqual(chal)
}
