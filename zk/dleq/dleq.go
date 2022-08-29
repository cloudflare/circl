// Package dleq provides zero-knowledge proofs of Discrete-Logarithm Equivalence (DLEQ).
//
// This implementation is compatible with the one used for VOPRFs [1].
// It supports batching proofs to amortize the cost of the proof generation and
// verification.
//
// References:
//
//	[1] draft-irtf-cfrg-voprf: https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
package dleq

import (
	"crypto"
	"encoding/binary"
	"io"

	"github.com/cloudflare/circl/group"
)

const (
	labelSeed         = "Seed-"
	labelChallenge    = "Challenge"
	labelComposite    = "Composite"
	labelHashToScalar = "HashToScalar-"
)

type Params struct {
	G   group.Group
	H   crypto.Hash
	DST []byte
}

type Proof struct {
	c, s group.Scalar
}

type Prover struct{ Params }

func (p Prover) Prove(k group.Scalar, a, ka, b, kb group.Element, rnd io.Reader) (*Proof, error) {
	return p.ProveBatch(k, a, ka, []group.Element{b}, []group.Element{kb}, rnd)
}

func (p Prover) ProveWithRandomness(k group.Scalar, a, ka, b, kb group.Element, rnd group.Scalar) (*Proof, error) {
	return p.ProveBatchWithRandomness(k, a, ka, []group.Element{b}, []group.Element{kb}, rnd)
}

func (p Prover) ProveBatch(k group.Scalar, a, ka group.Element, bi, kbi []group.Element, rnd io.Reader) (*Proof, error) {
	return p.ProveBatchWithRandomness(k, a, ka, bi, kbi, p.Params.G.RandomScalar(rnd))
}

func (p Prover) ProveBatchWithRandomness(
	k group.Scalar,
	a, ka group.Element,
	bi, kbi []group.Element,
	rnd group.Scalar,
) (*Proof, error) {
	M, Z, err := p.computeComposites(k, ka, bi, kbi)
	if err != nil {
		return nil, err
	}

	kAm, err := ka.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	a0, err := M.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	a1, err := Z.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	t2 := p.G.NewElement().Mul(a, rnd)
	a2, err := t2.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	t3 := p.G.NewElement().Mul(M, rnd)
	a3, err := t3.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	cc := p.doChallenge([5][]byte{kAm, a0, a1, a2, a3})
	ss := p.G.NewScalar()
	ss.Mul(cc, k)
	ss.Sub(rnd, ss)

	return &Proof{cc, ss}, nil
}

func (p Params) computeComposites(
	k group.Scalar,
	ka group.Element,
	bi []group.Element,
	kbi []group.Element,
) (m, z group.Element, err error) {
	kAm, err := ka.MarshalBinaryCompress()
	if err != nil {
		return nil, nil, err
	}

	lenBuf := []byte{0, 0}
	H := p.H.New()

	binary.BigEndian.PutUint16(lenBuf, uint16(len(kAm)))
	mustWrite(H, lenBuf)
	mustWrite(H, kAm)

	seedDST := append(append([]byte{}, labelSeed...), p.DST...)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(seedDST)))
	mustWrite(H, lenBuf)
	mustWrite(H, seedDST)

	seed := H.Sum(nil)

	m = p.G.Identity()
	z = p.G.Identity()
	h2sDST := append(append([]byte{}, labelHashToScalar...), p.DST...)
	for j := range bi {
		h2Input := []byte{}

		Bij, err := bi[j].MarshalBinaryCompress()
		if err != nil {
			return nil, nil, err
		}

		kBij, err := kbi[j].MarshalBinaryCompress()
		if err != nil {
			return nil, nil, err
		}

		binary.BigEndian.PutUint16(lenBuf, uint16(len(seed)))
		h2Input = append(append(h2Input, lenBuf...), seed...)

		binary.BigEndian.PutUint16(lenBuf, uint16(j))
		h2Input = append(h2Input, lenBuf...)

		binary.BigEndian.PutUint16(lenBuf, uint16(len(Bij)))
		h2Input = append(append(h2Input, lenBuf...), Bij...)

		binary.BigEndian.PutUint16(lenBuf, uint16(len(kBij)))
		h2Input = append(append(h2Input, lenBuf...), kBij...)

		h2Input = append(h2Input, labelComposite...)
		dj := p.G.HashToScalar(h2Input, h2sDST)
		Mj := p.G.NewElement()
		Mj.Mul(bi[j], dj)
		m.Add(m, Mj)

		if k == nil {
			Zj := p.G.NewElement()
			Zj.Mul(kbi[j], dj)
			z.Add(z, Zj)
		}
	}

	if k != nil {
		z.Mul(m, k)
	}

	return m, z, nil
}

func (p Params) doChallenge(a [5][]byte) group.Scalar {
	h2Input := []byte{}
	lenBuf := []byte{0, 0}

	for i := range a {
		binary.BigEndian.PutUint16(lenBuf, uint16(len(a[i])))
		h2Input = append(append(h2Input, lenBuf...), a[i]...)
	}

	h2Input = append(h2Input, labelChallenge...)
	dst := append(append([]byte{}, labelHashToScalar...), p.DST...)

	return p.G.HashToScalar(h2Input, dst)
}

type Verifier struct{ Params }

func (v Verifier) Verify(a, ka, b, kb group.Element, p *Proof) bool {
	return v.VerifyBatch(a, ka, []group.Element{b}, []group.Element{kb}, p)
}

func (v Verifier) VerifyBatch(a, ka group.Element, bi, kbi []group.Element, p *Proof) bool {
	g := v.Params.G
	M, Z, err := v.Params.computeComposites(nil, ka, bi, kbi)
	if err != nil {
		return false
	}

	sA := g.NewElement().Mul(a, p.s)
	ckA := g.NewElement().Mul(ka, p.c)
	t2 := g.NewElement().Add(sA, ckA)
	sM := g.NewElement().Mul(M, p.s)
	cZ := g.NewElement().Mul(Z, p.c)
	t3 := g.NewElement().Add(sM, cZ)

	kAm, err := ka.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	a0, err := M.MarshalBinaryCompress()
	if err != nil {
		return false
	}
	a1, err := Z.MarshalBinaryCompress()
	if err != nil {
		return false
	}
	a2, err := t2.MarshalBinaryCompress()
	if err != nil {
		return false
	}
	a3, err := t3.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	gotC := v.Params.doChallenge([5][]byte{kAm, a0, a1, a2, a3})

	return gotC.IsEqual(p.c)
}

func (p *Proof) MarshalBinary() ([]byte, error) {
	g := p.c.Group()
	scalarSize := int(g.Params().ScalarLength)
	output := make([]byte, 0, 2*scalarSize)

	serC, err := p.c.MarshalBinary()
	if err != nil {
		return nil, err
	}
	output = append(output, serC...)

	serS, err := p.s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	output = append(output, serS...)

	return output, nil
}

func (p *Proof) UnmarshalBinary(g group.Group, data []byte) error {
	scalarSize := int(g.Params().ScalarLength)
	if len(data) < 2*scalarSize {
		return io.ErrShortBuffer
	}

	c := g.NewScalar()
	err := c.UnmarshalBinary(data[:scalarSize])
	if err != nil {
		return err
	}

	s := g.NewScalar()
	err = s.UnmarshalBinary(data[scalarSize : 2*scalarSize])
	if err != nil {
		return err
	}

	p.c = c
	p.s = s

	return nil
}

func mustWrite(h io.Writer, bytes []byte) {
	bytesLen, err := h.Write(bytes)
	if err != nil {
		panic(err)
	}
	if len(bytes) != bytesLen {
		panic("dleq: failed to write on hash")
	}
}
