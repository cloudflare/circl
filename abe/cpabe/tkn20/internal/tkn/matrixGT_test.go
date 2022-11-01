package tkn

import (
	"crypto/rand"
	"testing"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
)

func TestRightMultLinearityGT(t *testing.T) {
	zpMat1, err := randomMatrixZp(rand.Reader, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	zpMat2, err := randomMatrixZp(rand.Reader, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	zpMat1p2 := newMatrixZp(3, 2)
	zpMat1p2.add(zpMat1, zpMat2)
	a, err := randomMatrixGT(rand.Reader, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	s := newMatrixGT(3, 3)
	u := newMatrixGT(3, 3)
	r := newMatrixGT(3, 3)
	tmp := newMatrixGT(3, 3)
	r.rightMult(a, zpMat1)
	s.rightMult(a, zpMat2)
	u.rightMult(a, zpMat1p2)
	tmp.add(r, s)
	if !tmp.Equal(u) {
		t.Fatal("failure of linearity")
	}
}

func TestLeftMultLinearityGT(t *testing.T) {
	zpMat1, err := randomMatrixZp(rand.Reader, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	zpMat2, err := randomMatrixZp(rand.Reader, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	zpMat1p2 := newMatrixZp(3, 3)
	zpMat1p2.add(zpMat1, zpMat2)
	a, err := randomMatrixGT(rand.Reader, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	s := newMatrixGT(0, 0)
	u := newMatrixGT(0, 0)
	r := newMatrixGT(0, 0)
	tmp := newMatrixGT(0, 0)
	r.leftMult(zpMat1, a)
	s.leftMult(zpMat2, a)
	u.leftMult(zpMat1p2, a)
	tmp.add(r, s)
	if !tmp.Equal(u) {
		t.Fatal("failure of linearity")
	}
}

func TestLeftMultActionGT(t *testing.T) {
	zpMat1, err := randomMatrixZp(rand.Reader, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	zpMat2, err := randomMatrixZp(rand.Reader, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	zpMat2m1 := newMatrixZp(3, 3)
	zpMat2m1.mul(zpMat2, zpMat1)
	a, err := randomMatrixGT(rand.Reader, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	s := newMatrixGT(0, 0)
	u := newMatrixGT(0, 0)
	r := newMatrixGT(0, 0)
	r.leftMult(zpMat1, a)
	s.leftMult(zpMat2, r)
	u.leftMult(zpMat2m1, a)
	if !s.Equal(u) {
		t.Fatal("failure of action")
	}
}

func TestRightMultActionGT(t *testing.T) {
	zpMat1, err := randomMatrixZp(rand.Reader, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	zpMat2, err := randomMatrixZp(rand.Reader, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	zpMat1m2 := newMatrixZp(2, 2)
	zpMat1m2.mul(zpMat1, zpMat2)
	a, err := randomMatrixGT(rand.Reader, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	s := newMatrixGT(0, 0)
	u := newMatrixGT(0, 0)
	r := newMatrixGT(0, 0)
	r.rightMult(a, zpMat1)
	s.rightMult(r, zpMat2)
	u.rightMult(a, zpMat1m2)
	if !s.Equal(u) {
		t.Fatal("failure of action")
	}
}

func TestExpGT(t *testing.T) {
	a, err := randomMatrixZp(rand.Reader, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomMatrixZp(rand.Reader, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	ab := newMatrixZp(2, 2)
	ab.mul(a, b)
	aexp := newMatrixGT(0, 0)
	aexp.exp(a)
	abexp := newMatrixGT(0, 0)
	abexp.exp(ab)
	abres := newMatrixGT(0, 0)
	abres.rightMult(aexp, b)
	if !abres.Equal(abexp) {
		t.Fatal("action and exp failure")
	}
}

func TestExpGTLinearity(t *testing.T) {
	a, err := randomMatrixZp(rand.Reader, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomMatrixZp(rand.Reader, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	ab := newMatrixZp(2, 2)
	ab.add(a, b)
	aexp := newMatrixGT(0, 0)
	aexp.exp(a)
	bexp := newMatrixGT(0, 0)
	bexp.exp(b)
	abexp := newMatrixGT(0, 0)
	absum := newMatrixGT(0, 0)
	absum.add(aexp, bexp)
	abexp.exp(ab)
	if !abexp.Equal(absum) {
		t.Fatal("linearity of exponentation broken")
	}
}

func TestExpKnownAnswer(t *testing.T) {
	a := eye(2)
	b := newMatrixGT(0, 0)
	b.exp(a)
	one := &pairing.Gt{}
	one.SetIdentity()
	if !b.entries[0].IsEqual(gtBaseVal) {
		t.Fatal("failure of 0")
	}
	if !b.entries[1].IsEqual(one) {
		t.Fatal("failure of 1")
	}
	if !b.entries[2].IsEqual(one) {
		t.Fatal("failure of 2")
	}
	if !b.entries[3].IsEqual(gtBaseVal) {
		t.Fatal("failure of 3")
	}
}

func TestMarshalGt(t *testing.T) {
	a, err := randomMatrixGT(rand.Reader, 7, 9)
	if err != nil {
		t.Fatal(err)
	}
	data, err := a.marshalBinary()
	if err != nil {
		t.Fatalf("failure to serialize: %s", err)
	}
	b := newMatrixGT(0, 0)
	err = b.unmarshalBinary(data)
	if err != nil {
		t.Fatalf("failure to deserialize: %s", err)
	}
	if !a.Equal(b) {
		t.Fatal("failure to roundtrip")
	}
	c := newMatrixGT(0, 0)
	err = c.unmarshalBinary(data[0 : len(data)-2])
	if err == nil {
		t.Fatalf("data is too short, deserialization should fail")
	}
}

func TestAliasLeftMultGT(t *testing.T) {
	a, err := randomMatrixGT(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	b, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	aCopy := newMatrixGT(4, 4)
	aCopy.set(a)
	bCopy := newMatrixZp(4, 4)
	bCopy.set(b)
	a.leftMult(b, a)
	res := newMatrixGT(0, 0)
	res.leftMult(bCopy, aCopy)
	if !res.Equal(a) {
		t.Fatalf("failure of leftMult to be alias safe")
	}
}

func TestAliasRightMultGT(t *testing.T) {
	a, err := randomMatrixGT(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	b, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	aCopy := newMatrixGT(4, 4)
	aCopy.set(a)
	bCopy := newMatrixZp(4, 4)
	bCopy.set(b)
	a.rightMult(a, b)
	res := newMatrixGT(0, 0)
	res.rightMult(aCopy, bCopy)
	if !res.Equal(a) {
		t.Fatalf("failure of rightMult to be alias safe")
	}
}

func TestAliasAddGt(t *testing.T) {
	a, err := randomMatrixG1(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	b, err := randomMatrixG1(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	aCopy := newMatrixG1(4, 4)
	aCopy.set(a)
	bCopy := newMatrixG1(4, 4)
	bCopy.set(b)
	a.add(b, a)
	res := newMatrixG1(0, 0)
	res.add(bCopy, aCopy)
	if !res.Equal(a) {
		t.Fatalf("failure of add to be alias safe")
	}
}
