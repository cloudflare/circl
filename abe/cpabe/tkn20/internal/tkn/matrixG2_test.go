package tkn

import (
	"crypto/rand"
	"testing"
)

func TestRightMultLinearityG2(t *testing.T) {
	zpMat1, err := randomMatrixZp(rand.Reader, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	zpMat2, err := randomMatrixZp(rand.Reader, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	zpMat1p2 := newMatrixZp(2, 3)
	zpMat1p2.add(zpMat1, zpMat2)
	a, err := randomMatrixG2(rand.Reader, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	s := newMatrixG2(3, 3)
	u := newMatrixG2(3, 3)
	r := newMatrixG2(3, 3)
	tmp := newMatrixG2(3, 3)
	r.rightMult(a, zpMat1)
	s.rightMult(a, zpMat2)
	u.rightMult(a, zpMat1p2)
	tmp.add(r, s)
	if !tmp.Equal(u) {
		t.Fatal("failure of linearity")
	}
}

func TestLeftMultLinearityG2(t *testing.T) {
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
	a, err := randomMatrixG2(rand.Reader, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	s := newMatrixG2(0, 0)
	u := newMatrixG2(0, 0)
	r := newMatrixG2(0, 0)
	tmp := newMatrixG2(0, 0)
	r.leftMult(zpMat1, a)
	s.leftMult(zpMat2, a)
	u.leftMult(zpMat1p2, a)
	tmp.add(r, s)
	if !tmp.Equal(u) {
		t.Fatal("failure of linearity")
	}
}

func TestLeftMultActionG2(t *testing.T) {
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
	a, err := randomMatrixG2(rand.Reader, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	s := newMatrixG2(0, 0)
	u := newMatrixG2(0, 0)
	r := newMatrixG2(0, 0)
	r.leftMult(zpMat1, a)
	s.leftMult(zpMat2, r)
	u.leftMult(zpMat2m1, a)
	if !s.Equal(u) {
		t.Fatal("failure of action")
	}
}

func TestRightMultActionG2(t *testing.T) {
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
	a, err := randomMatrixG2(rand.Reader, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	s := newMatrixG2(0, 0)
	u := newMatrixG2(0, 0)
	r := newMatrixG2(0, 0)
	r.rightMult(a, zpMat1)
	s.rightMult(r, zpMat2)
	u.rightMult(a, zpMat1m2)
	if !s.Equal(u) {
		t.Fatal("failure of action")
	}
}

func TestExpG2(t *testing.T) {
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
	aexp := newMatrixG2(0, 0)
	aexp.exp(a)
	abexp := newMatrixG2(0, 0)
	abexp.exp(ab)
	abres := newMatrixG2(0, 0)
	abres.rightMult(aexp, b)
	if !abres.Equal(abexp) {
		t.Fatal("action and exp failure")
	}
}

func TestMarshalG2(t *testing.T) {
	a, err := randomMatrixG2(rand.Reader, 7, 9)
	if err != nil {
		t.Fatal(err)
	}
	data, err := a.marshalBinary()
	if err != nil {
		t.Fatalf("failure to serialize: %s", err)
	}
	b := newMatrixG2(0, 0)
	err = b.unmarshalBinary(data)
	if err != nil {
		t.Fatalf("failure to deserialize: %s", err)
	}
	if !a.Equal(b) {
		t.Fatal("failure to roundtrip")
	}
	c := newMatrixG2(0, 0)
	err = c.unmarshalBinary(append(data, 0))
	if err == nil {
		t.Fatalf("data has excess bytes, deserialization should fail")
	}
}

func TestAliasLeftMultG2(t *testing.T) {
	a, err := randomMatrixG2(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	b, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	aCopy := newMatrixG2(4, 4)
	aCopy.set(a)
	bCopy := newMatrixZp(4, 4)
	bCopy.set(b)
	a.leftMult(b, a)
	res := newMatrixG2(0, 0)
	res.leftMult(bCopy, aCopy)
	if !res.Equal(a) {
		t.Fatalf("failure of leftMult to be alias safe")
	}
}

func TestAliasRightMultG2(t *testing.T) {
	a, err := randomMatrixG2(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	b, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	aCopy := newMatrixG2(4, 4)
	aCopy.set(a)
	bCopy := newMatrixZp(4, 4)
	bCopy.set(b)
	a.rightMult(a, b)
	res := newMatrixG2(0, 0)
	res.rightMult(aCopy, bCopy)
	if !res.Equal(a) {
		t.Fatalf("failure of rightMult to be alias safe")
	}
}

func TestAliasAddG2(t *testing.T) {
	a, err := randomMatrixG2(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	b, err := randomMatrixG2(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	aCopy := newMatrixG2(4, 4)
	aCopy.set(a)
	bCopy := newMatrixG2(4, 4)
	bCopy.set(b)
	a.add(b, a)
	res := newMatrixG2(0, 0)
	res.add(bCopy, aCopy)
	if !res.Equal(a) {
		t.Fatalf("failure of add to be alias safe")
	}
}
