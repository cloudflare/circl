// Implements the scheme of https://eprint.iacr.org/2019/966

package tkn

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
)

type PublicParams struct {
	b2  *matrixG2
	wb1 *matrixG1
	btk *matrixGT
}

func (p *PublicParams) MarshalBinary() ([]byte, error) {
	b2Bytes, err := p.b2.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("PublicParams serializing failed: %w", err)
	}
	ret := appendLenPrefixed(nil, b2Bytes)

	wb1Bytes, err := p.wb1.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("PublicParams serializing failed: %w", err)
	}
	ret = appendLenPrefixed(ret, wb1Bytes)

	btkBytes, err := p.btk.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("PublicParams serializing failed: %w", err)
	}
	ret = appendLenPrefixed(ret, btkBytes)

	return ret, nil
}

func (p *PublicParams) UnmarshalBinary(data []byte) error {
	b2Bytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("PublicParams deserialization failure: %w", err)
	}
	p.b2 = newMatrixG2(0, 0)
	err = p.b2.unmarshalBinary(b2Bytes)
	if err != nil {
		return fmt.Errorf("PublicParams deserialization failure: %w", err)
	}

	wb1Bytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("PublicParams deserialization failure: %w", err)
	}
	p.wb1 = newMatrixG1(0, 0)
	err = p.wb1.unmarshalBinary(wb1Bytes)
	if err != nil {
		return fmt.Errorf("PublicParams deserialization failure: %w", err)
	}

	btkBytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("PublicParams deserialization failure: %w", err)
	}
	p.btk = newMatrixGT(0, 0)
	err = p.btk.unmarshalBinary(btkBytes)
	if err != nil {
		return fmt.Errorf("PublicParams deserialization failure: %w", err)
	}

	if len(data) != 0 {
		return fmt.Errorf("PublicParams deserialization failed: excess bytes remain in data")
	}
	return nil
}

func (p *PublicParams) Equal(p2 *PublicParams) bool {
	return p.b2.Equal(p2.b2) && p.wb1.Equal(p2.wb1) && p.btk.Equal(p2.btk)
}

type SecretParams struct {
	a       *matrixZp
	wtA     *matrixZp
	bstar   *matrixZp
	bstar12 *matrixZp
	k       *matrixZp // vectors are represented as 1 x n matrices
	prfKey  []byte
}

func (s *SecretParams) MarshalBinary() ([]byte, error) {
	aBytes, err := s.a.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("SecretParams serializing failed: %w", err)
	}
	wtABytes, err := s.wtA.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("SecretParams serializing failed: %w", err)
	}
	bstarBytes, err := s.bstar.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("SecretParams serializing failed: %w", err)
	}
	bstar12Bytes, err := s.bstar12.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("SecretParams serializing failed: %w", err)
	}
	kBytes, err := s.k.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("SecretParams serializing failed: %w", err)
	}
	bufs := [][]byte{
		aBytes, wtABytes, bstarBytes, bstar12Bytes, kBytes, s.prfKey,
	}

	ret := appendLenPrefixed(nil, bufs[0])
	for _, buf := range bufs[1:] {
		ret = appendLenPrefixed(ret, buf)
	}
	return ret, nil
}

func (s *SecretParams) UnmarshalBinary(data []byte) error {
	aBytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	s.a = newMatrixZp(0, 0)
	err = s.a.unmarshalBinary(aBytes)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	wtABytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	s.wtA = newMatrixZp(0, 0)
	err = s.wtA.unmarshalBinary(wtABytes)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	bstarBytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	s.bstar = newMatrixZp(0, 0)
	err = s.bstar.unmarshalBinary(bstarBytes)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	bstar12Bytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	s.bstar12 = newMatrixZp(0, 0)
	err = s.bstar12.unmarshalBinary(bstar12Bytes)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	kBytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	s.k = newMatrixZp(0, 0)
	err = s.k.unmarshalBinary(kBytes)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	prfBytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("SecretParams deserialization failure: %w", err)
	}
	s.prfKey = prfBytes

	if len(data) != 0 {
		return fmt.Errorf("SecretParams deserialization failed: excess bytes remain in data")
	}
	return nil
}

func (s *SecretParams) Equal(s2 *SecretParams) bool {
	return s.a.Equal(s2.a) && s.wtA.Equal(s2.wtA) && s.bstar.Equal(s2.bstar) &&
		s.bstar12.Equal(s2.bstar12) && s.k.Equal(s2.k) &&
		subtle.ConstantTimeCompare(s.prfKey, s2.prfKey) == 1
}

type AttributesKey struct {
	a      *Attributes
	k1     *matrixG2
	k2     *matrixG1
	k3     map[string]*matrixG1
	k3wild map[string]*matrixG1 // only contains wildcards
}

func (a *AttributesKey) MarshalBinary() ([]byte, error) {
	aBytes, err := a.a.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("AttributesKey serializing failed: %w", err)
	}
	ret := appendLenPrefixed(nil, aBytes)
	k1Bytes, err := a.k1.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("AttributesKey serializing failed: %w", err)
	}
	ret = appendLenPrefixed(ret, k1Bytes)
	k2Bytes, err := a.k2.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("AttributesKey serializing failed: %w", err)
	}
	ret = appendLenPrefixed(ret, k2Bytes)
	ret = append(ret, 0, 0)
	binary.LittleEndian.PutUint16(ret[len(ret)-2:], uint16(len(a.k3)))
	k3Bytes, err := marshalBinarySortedMapMatrixG1(a.k3)
	if err != nil {
		return nil, fmt.Errorf("AttributesKey serializing failed: %w", err)
	}
	ret = append(ret, k3Bytes...)

	ret = append(ret, 0, 0)
	binary.LittleEndian.PutUint16(ret[len(ret)-2:], uint16(len(a.k3wild)))
	k3wildBytes, err := marshalBinarySortedMapMatrixG1(a.k3wild)
	if err != nil {
		return nil, fmt.Errorf("AttributesKey serializing failed: %w", err)
	}
	ret = append(ret, k3wildBytes...)

	return ret, nil
}

func (a *AttributesKey) UnmarshalBinary(data []byte) error {
	aBytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("AttributesKey deserialization failure: %w", err)
	}
	a.a = &Attributes{}
	err = a.a.unmarshalBinary(aBytes)
	if err != nil {
		return fmt.Errorf("AttributesKey deserialization failure: %w", err)
	}
	k1Bytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("AttributesKey deserialization failure: %w", err)
	}
	a.k1 = newMatrixG2(0, 0)
	err = a.k1.unmarshalBinary(k1Bytes)
	if err != nil {
		return fmt.Errorf("AttributesKey deserialization failure: %w", err)
	}
	k2Bytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return fmt.Errorf("AttributesKey deserialization failure: %w", err)
	}
	a.k2 = newMatrixG1(0, 0)
	err = a.k2.unmarshalBinary(k2Bytes)
	if err != nil {
		return fmt.Errorf("AttributesKey deserialization failure: %w", err)
	}

	if len(data) < 2 {
		return fmt.Errorf("AttributesKey deserialization failure: data too short")
	}
	n := int(binary.LittleEndian.Uint16(data))
	data = data[2:]
	a.k3 = make(map[string]*matrixG1, n)
	for i := 0; i < n; i++ {
		sBytes, rem, err := removeLenPrefixed(data)
		if err != nil {
			return fmt.Errorf("AttributesKey deserialization failure: %w", err)
		}
		mBytes, rem, err := removeLenPrefixed(rem)
		if err != nil {
			return fmt.Errorf("AttributesKey deserialization failure: %w", err)
		}
		m := newMatrixG1(0, 0)
		err = m.unmarshalBinary(mBytes)
		if err != nil {
			return fmt.Errorf("AttributesKey deserialization failure: %w", err)
		}
		a.k3[string(sBytes)] = m
		data = rem
	}

	if len(data) < 2 {
		return fmt.Errorf("AttributesKey deserialization failure: data too short")
	}
	n = int(binary.LittleEndian.Uint16(data))
	data = data[2:]
	a.k3wild = make(map[string]*matrixG1, n)
	for i := 0; i < n; i++ {
		sBytes, rem, err := removeLenPrefixed(data)
		if err != nil {
			return fmt.Errorf("AttributesKey deserialization failure: %w", err)
		}
		mBytes, rem, err := removeLenPrefixed(rem)
		if err != nil {
			return fmt.Errorf("AttributesKey deserialization failure: %w", err)
		}
		m := newMatrixG1(0, 0)
		err = m.unmarshalBinary(mBytes)
		if err != nil {
			return fmt.Errorf("AttributesKey deserialization failure: %w", err)
		}
		a.k3wild[string(sBytes)] = m
		data = rem
	}
	if len(data) != 0 {
		return fmt.Errorf("AttributesKey deserialization failed: excess bytes remain in data")
	}
	return nil
}

func (a *AttributesKey) Equal(b *AttributesKey) bool {
	if !a.a.Equal(b.a) || !a.k1.Equal(b.k1) || !a.k2.Equal(b.k2) {
		return false
	}
	if len(a.k3) != len(b.k3) || len(a.k3wild) != len(b.k3wild) {
		return false
	}
	for k, v := range a.k3 {
		if !b.k3[k].Equal(v) {
			return false
		}
	}
	for k, v := range a.k3wild {
		if !b.k3wild[k].Equal(v) {
			return false
		}
	}
	return true
}

type ciphertextHeader struct {
	p     *Policy
	c1    *matrixG2
	c2    []*matrixG2
	c3    []*matrixG1
	c3neg []*matrixG1 // additional vector for negated attributes
}

func (hdr *ciphertextHeader) marshalBinary() ([]byte, error) {
	pBytes, err := hdr.p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ret := appendLenPrefixed(nil, pBytes)

	c1Bytes, err := hdr.c1.marshalBinary()
	if err != nil {
		return nil, fmt.Errorf("c1 serializing: %w", err)
	}
	ret = appendLenPrefixed(ret, c1Bytes)

	// Now we need to indicate how long c2, c3, c3neg are.
	// Each array will be the same size (or nil), so with more work we can specalize
	// but for now we will ignore that.

	c2Len := len(hdr.c2)

	ret = append(ret, 0, 0)
	binary.LittleEndian.PutUint16(ret[len(ret)-2:], uint16(c2Len))
	for i := 0; i < c2Len; i++ {
		c2dat, errM := hdr.c2[i].marshalBinary()
		if errM != nil {
			return nil, fmt.Errorf("c2 serializing %d: %w", i, errM)
		}
		ret = appendLenPrefixed(ret, c2dat)
	}
	c3Len := len(hdr.c3)
	ret = append(ret, 0, 0)
	binary.LittleEndian.PutUint16(ret[len(ret)-2:], uint16(c3Len))
	for i := 0; i < c3Len; i++ {
		c3dat, errM := hdr.c3[i].marshalBinary()
		if errM != nil {
			return nil, fmt.Errorf("c3 serializing %d: %w", i, errM)
		}
		ret = appendLenPrefixed(ret, c3dat)
	}
	for i := 0; i < c3Len; i++ {
		var c3negdat []byte
		if hdr.c3neg[i] != nil {
			c3negdat, err = hdr.c3neg[i].marshalBinary()
			if err != nil {
				return nil, fmt.Errorf("c3neg serializing %d: %w", i, err)
			}
		} else {
			c3negdat = nil
		}
		ret = appendLenPrefixed(ret, c3negdat)
	}
	return ret, nil
}

func (hdr *ciphertextHeader) unmarshalBinary(data []byte) error {
	pBytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return err
	}
	hdr.p = new(Policy)
	err = hdr.p.UnmarshalBinary(pBytes)
	if err != nil {
		return err
	}
	c1Bytes, data, err := removeLenPrefixed(data)
	if err != nil {
		return err
	}
	hdr.c1 = newMatrixG2(0, 0)
	err = hdr.c1.unmarshalBinary(c1Bytes)
	if err != nil {
		return err
	}
	c2Len := int(binary.LittleEndian.Uint16(data))
	hdr.c2 = make([]*matrixG2, c2Len)
	data = data[2:]
	var c2data []byte
	var c3data []byte
	var c3negdata []byte

	for i := 0; i < c2Len; i++ {
		c2data, data, err = removeLenPrefixed(data)
		if err != nil {
			return err
		}
		hdr.c2[i] = newMatrixG2(0, 0)
		err = hdr.c2[i].unmarshalBinary(c2data)
		if err != nil {
			return err
		}
	}

	c3Len := int(binary.LittleEndian.Uint16(data))
	hdr.c3 = make([]*matrixG1, c3Len)
	hdr.c3neg = make([]*matrixG1, c3Len)
	data = data[2:]

	for i := 0; i < c3Len; i++ {
		c3data, data, err = removeLenPrefixed(data)
		if err != nil {
			return err
		}
		hdr.c3[i] = newMatrixG1(0, 0)
		err = hdr.c3[i].unmarshalBinary(c3data)
		if err != nil {
			return err
		}
	}

	for i := 0; i < c3Len; i++ {
		c3negdata, data, err = removeLenPrefixed(data)
		if err != nil {
			return err
		}

		if len(c3negdata) != 0 {
			hdr.c3neg[i] = newMatrixG1(0, 0)
			err = hdr.c3neg[i].unmarshalBinary(c3negdata)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func GenerateParams(rand io.Reader) (*PublicParams, *SecretParams, error) {
	A, err := sampleDlin(rand)
	if err != nil {
		return nil, nil, err
	}
	Bbar, err := randomMatrixZp(rand, 4, 4)
	if err != nil {
		return nil, nil, err
	}
	W, err := randomMatrixZp(rand, 3, 4)
	if err != nil {
		return nil, nil, err
	}
	k, err := randomMatrixZp(rand, 4, 1)
	if err != nil {
		return nil, nil, err
	}
	prfKey := make([]byte, 16)
	_, err = io.ReadFull(rand, prfKey)
	if err != nil {
		return nil, nil, err
	}

	B := newMatrixZp(0, 0)
	B.colsel(Bbar, []int{0, 1})
	wb := newMatrixZp(0, 0)
	wb.mul(W, B)

	Bt := newMatrixZp(0, 0)
	Bt.transpose(B)
	BtKp := newMatrixZp(0, 0)
	BtKp.mul(Bt, k)

	pp := PublicParams{}
	pp.b2 = newMatrixG2(0, 0)
	pp.b2.exp(B)
	pp.wb1 = newMatrixG1(0, 0)
	pp.wb1.exp(wb)
	pp.btk = newMatrixGT(0, 0)
	pp.btk.exp(BtKp)

	sp := SecretParams{}
	sp.a = A
	sp.wtA = newMatrixZp(0, 0)
	wt := newMatrixZp(0, 0)
	wt.transpose(W)
	sp.wtA.mul(wt, A)

	BbarTinv := newMatrixZp(0, 0)
	BbarT := newMatrixZp(0, 0)
	BbarT.transpose(Bbar)
	err = BbarTinv.inverse(BbarT)
	if err != nil {
		return nil, nil, err
	}

	sp.bstar = newMatrixZp(0, 0)
	sp.bstar.colsel(BbarTinv, []int{0, 1})

	sp.bstar12 = newMatrixZp(0, 0)
	sp.bstar12.colsel(BbarTinv, []int{2, 3})

	sp.k = k
	sp.prfKey = prfKey

	return &pp, &sp, nil
}

func max(in []int) int {
	max := 0
	for i := 0; i < len(in); i++ {
		if in[i] > max {
			max = in[i]
		}
	}
	return max
}

// encapsulate creates a new ephemeral key and header that can be opened to it. This is
// the transformation of an Elgamal like scheme to a KEM.
func encapsulate(rand io.Reader, pp *PublicParams, policy *Policy) (*ciphertextHeader, *pairing.Gt, error) {
	pi := policy.pi()
	d := max(pi) + 1
	ri := make([]*matrixZp, d)
	r, err := randomMatrixZp(rand, 2, 1)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < d; i++ {
		ri[i], err = randomMatrixZp(rand, 2, 1)
		if err != nil {
			return nil, nil, err
		}
	}
	rshares, err := policy.F.share(rand, r)
	if err != nil {
		return nil, nil, err
	}
	tmp := newMatrixZp(2, 1)
	wshares := make([]*matrixG1, len(rshares))
	for i := 0; i < len(rshares); i++ {
		wshares[i] = newMatrixG1(0, 0)
		wshares[i].rightMult(pp.wb1, rshares[i])
	}

	c1 := newMatrixG2(0, 0)
	c1.rightMult(pp.b2, r)

	c2 := make([]*matrixG2, d)
	for i := 0; i < d; i++ {
		c2[i] = newMatrixG2(0, 0)
		c2[i].rightMult(pp.b2, ri[i])
	}

	c4mat := newMatrixGT(1, 1)
	tmp.transpose(r)
	c4mat.leftMult(tmp, pp.btk)
	if c4mat.rows != 1 || c4mat.cols != 1 {
		panic("failure to get the encryption right")
	}

	c3 := make([]*matrixG1, len(policy.Inputs))
	c3neg := make([]*matrixG1, len(policy.Inputs))
	for i := 0; i < len(policy.Inputs); i++ {
		U0, U1 := oracle([]byte(policy.Inputs[i].Label))
		if policy.Inputs[i].Positive {
			c3[i] = newMatrixG1(0, 0)

			c3[i].scalarMult(policy.Inputs[i].Value, U0)
			c3[i].add(c3[i], U1)
			c3[i].rightMult(c3[i], ri[pi[i]])
			c3[i].add(c3[i], wshares[i])
			c3neg[i] = nil
		} else {
			c3[i] = newMatrixG1(0, 0)
			c3[i].rightMult(U0, ri[pi[i]])
			c3[i].sub(c3[i], wshares[i])

			c3neg[i] = newMatrixG1(0, 0)
			c3neg[i].rightMult(U1, ri[pi[i]])
			tmpmat := newMatrixG1(0, 0)
			tmpmat.scalarMult(policy.Inputs[i].Value, wshares[i])
			c3neg[i].add(c3neg[i], tmpmat)
		}
	}
	return &ciphertextHeader{
		p:     policy,
		c1:    c1,
		c2:    c2,
		c3:    c3,
		c3neg: c3neg,
	}, &c4mat.entries[0], nil
}

func deriveAttributeKeys(rand io.Reader, sp *SecretParams, attrs *Attributes) (*AttributesKey, error) {
	s, err := randomMatrixZp(rand, 2, 1)
	if err != nil {
		return nil, err
	}
	As := newMatrixZp(0, 0)

	k1 := newMatrixG2(0, 0)
	As.mul(sp.a, s)
	k1.exp(As)
	Ast := newMatrixZp(0, 0)
	Ast.transpose(As)

	k2 := newMatrixG1(0, 0)
	tmp := newMatrixZp(0, 0)
	tmp.mul(sp.wtA, s)
	tmp.add(tmp, sp.k)
	k2.exp(tmp)

	k3 := make(map[string]*matrixG1)
	k3wild := make(map[string]*matrixG1)
	for label, attr := range *attrs {
		if attr.wild {
			// For wild k3 is y term, k3wild is constant term
			U0, U1 := oracle([]byte(label))
			V0, V1, err := prf(sp.prfKey, []byte(label))
			if err != nil {
				return nil, err
			}
			k3[label] = newMatrixG1(0, 0)
			k3wild[label] = newMatrixG1(0, 0)
			left := newMatrixG1(0, 0)
			right := newMatrixG1(0, 0)

			left.transpose(U0)
			left.leftMult(sp.bstar, left)
			left.rightMult(left, As)

			tmp.transpose(V0)
			tmp.mul(sp.bstar12, tmp)
			tmp.mul(tmp, As)

			right.exp(tmp)

			k3[label].add(left, right)

			left.transpose(U1)
			left.leftMult(sp.bstar, left)
			left.rightMult(left, As)

			tmp.transpose(V1)
			tmp.mul(sp.bstar12, tmp)
			tmp.mul(tmp, As)

			right.exp(tmp)

			k3wild[label].add(left, right)
		} else {
			U0, U1 := oracle([]byte(label))
			V0, V1, err := prf(sp.prfKey, []byte(label))
			if err != nil {
				return nil, err
			}

			k3[label] = newMatrixG1(0, 0)
			left := newMatrixG1(0, 0)
			right := newMatrixG1(0, 0)

			left.scalarMult(attr.Value, U0)
			left.add(U1, left)
			left.transpose(left)
			left.leftMult(sp.bstar, left)
			left.rightMult(left, As)

			tmp.scalarmul(attr.Value, V0)
			tmp.add(tmp, V1)
			tmp.transpose(tmp)
			tmp.mul(sp.bstar12, tmp)
			tmp.mul(tmp, As)

			right.exp(tmp)

			k3[label].add(left, right)
		}
	}

	return &AttributesKey{
		a:      attrs,
		k1:     k1,
		k2:     k2,
		k3:     k3,
		k3wild: k3wild,
	}, nil
}

// Decapsulate decapsulates
func decapsulate(header *ciphertextHeader, key *AttributesKey) (*pairing.Gt, error) {
	// First we need to determine the satisfying assignment: which attributes in attr
	// are needed.

	// We use pi to determine which D to sum into
	pi := header.p.pi()
	d := max(pi) + 1
	// p1, p2 are the left halves of the pairings.
	p1 := make([]*matrixG1, d)
	p2 := make([]*matrixG1, d)

	sat, err := header.p.Satisfaction(key.a)
	if err != nil {
		return nil, err
	}
	for k := 0; k < len(sat.matches); k++ {
		match := sat.matches[k]
		j := pi[match.wire]

		if p1[j] == nil {
			p1[j] = newMatrixG1(header.c3[match.wire].rows, header.c3[match.wire].cols)
		}
		if p2[j] == nil {
			p2[j] = newMatrixG1(key.k3[match.label].rows, key.k3[match.label].cols)
		}
		if header.p.Inputs[match.wire].Positive {
			p1[j].add(p1[j], header.c3[match.wire])

			if (*key.a)[match.label].wild {
				if key.k3wild[match.label] == nil {
					return nil, fmt.Errorf("missing wildcard data for Label %s", match.label)
				}
				y := header.p.Inputs[match.wire].Value
				tmp1 := newMatrixG1(0, 0)
				tmp1.scalarMult(y, key.k3[match.label])
				tmp1.add(tmp1, key.k3wild[match.label])
				p2[j].add(p2[j], tmp1)
			} else {
				p2[j].add(p2[j], key.k3[match.label])
			}
		} else {
			keymat := newMatrixG1(0, 0)
			y := &pairing.Scalar{}

			if (*key.a)[match.label].wild {
				y.Add(header.p.Inputs[match.wire].Value, ToScalar(1))
				keymat.scalarMult(y, key.k3[match.label])
				keymat.add(keymat, key.k3wild[match.label])
			} else {
				y.Set((*(key.a))[match.label].Value)
				keymat.set(key.k3[match.label])
			}
			diff := &pairing.Scalar{}

			diff.Sub(header.p.Inputs[match.wire].Value, y)
			diff.Inv(diff)
			p1add := newMatrixG1(0, 0)
			p1add.scalarMult(y, header.c3[match.wire])
			p1add.add(p1add, header.c3neg[match.wire])
			p1add.scalarMult(diff, p1add)

			p2add := newMatrixG1(0, 0)
			p2add.scalarMult(diff, keymat)

			p1[j].add(p1[j], p1add)
			p2[j].add(p2[j], p2add)
		}
	}

	pairs := &pairAccum{}

	var pTot *matrixG1
	for i := 0; i < d; i++ {
		if p1[i] != nil {
			if pTot == nil {
				pTot = newMatrixG1(p1[i].rows, p1[i].cols)
			}
			pTot.add(pTot, p1[i])
			pairs.addDuals(p2[i], header.c2[i], 1)
		}
	}
	pairs.addDuals(pTot, key.k1, -1)
	pairs.addDuals(key.k2.copy(), header.c1, 1)

	return pairs.eval(), nil
}
