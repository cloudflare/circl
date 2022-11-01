package tkn

import (
	"crypto/rand"
	"testing"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

func TestSampleDlin(t *testing.T) {
	_, err := sampleDlin(rand.Reader)
	if err != nil {
		t.Errorf("failure of dlin: %s", err)
	}
}

func TestAdditionAndTranspose(t *testing.T) {
	a, err := sampleDlin(rand.Reader)
	if err != nil {
		t.Errorf("failure of dlin: %s", err)
	}
	b, err := sampleDlin(rand.Reader)
	if err != nil {
		t.Errorf("failure of dlin: %s", err)
	}
	at := new(matrixZp)
	bt := new(matrixZp)
	aplusb := new(matrixZp)
	atplusbt := new(matrixZp)
	lhs := new(matrixZp)

	at.transpose(a)
	bt.transpose(b)
	aplusb.add(a, b)
	atplusbt.add(at, bt)

	lhs.transpose(atplusbt)
	if !aplusb.Equal(lhs) {
		t.Errorf("failure of equality")
	}
}

func TestMultiplication(t *testing.T) {
	a, err := sampleDlin(rand.Reader)
	if err != nil {
		t.Errorf("failure of diln: %s", err)
	}
	b, err := sampleDlin(rand.Reader)
	if err != nil {
		t.Errorf("failure of diln: %s", err)
	}
	bta := new(matrixZp)
	atb := new(matrixZp)
	tmp := new(matrixZp)
	tmp.transpose(b)
	bta.mul(tmp, a)
	tmp.transpose(a)
	atb.mul(tmp, b)
	tmp.transpose(atb)
	if !tmp.Equal(bta) {
		t.Errorf("failure of multiplication")
	}
}

func TestInverse(t *testing.T) {
	a, err := sampleDlin(rand.Reader)
	if err != nil {
		t.Errorf("failure of diln: %s", err)
	}
	aa := new(matrixZp)
	at := new(matrixZp)
	ainv := new(matrixZp)
	res := new(matrixZp)
	at.transpose(a)
	aa.mul(at, a)
	err = ainv.inverse(aa)
	if err != nil {
		t.Errorf("failure to compute inverse")
	}
	res.mul(ainv, aa)
	expected := eye(res.cols)
	if !expected.Equal(res) {
		t.Errorf("failure of inverse value: expected:\n%v\n got:\n%v", expected, res)
		t.Errorf("inversion was of %v\n", aa)
	}
	res.mul(aa, ainv)
	if !expected.Equal(res) {
		t.Errorf("failure of reversed mult: got\n%v\n", res)
	}
}

func TestInverse2x2(t *testing.T) {
	A, err := randomMatrixZp(rand.Reader, 2, 2)
	if err != nil {
		t.Fatalf("failure of random: %v", err)
	}

	B := newMatrixZp(2, 2)
	C := newMatrixZp(2, 2)
	err = C.inverse(A)
	if err != nil {
		t.Fatalf("ah, we have a problem: try again")
	}
	var a pairing.Scalar
	var b pairing.Scalar
	var c pairing.Scalar
	var d pairing.Scalar
	var det pairing.Scalar
	var tmp pairing.Scalar
	a.Set(&A.entries[0])
	b.Set(&A.entries[1])
	c.Set(&A.entries[2])
	d.Set(&A.entries[3])
	det.Mul(&a, &d)
	tmp.Mul(&b, &c)
	det.Sub(&det, &tmp)
	tmp.Inv(&det)
	B.entries[0].Set(&d)
	B.entries[1].Set(&b)
	B.entries[1].Neg()
	B.entries[2].Set(&c)
	B.entries[2].Neg()
	B.entries[3].Set(&a)
	B.scalarmul(&tmp, B)
	if !C.Equal(B) {
		t.Errorf("failure to agree with explicit formula: got:\n%v, wanted\n%v\n", B, C)
	}
	expected := eye(2)
	res := newMatrixZp(0, 0)
	res.mul(B, A)
	if !res.Equal(expected) {
		t.Errorf("explicit formula wrong: got:\n%v\n as inverse of\n%v\n", B, A)
	}
}

func TestPRF(t *testing.T) {
	m1, m2, err := prf([]byte("test key do not use"), []byte("some input"))
	if err != nil {
		t.Errorf("failure of prf: %s", err)
	}
	if m1.Equal(m2) {
		t.Errorf("prf fails to have distinct outputs")
	}
	m3, _, err := prf([]byte("test key do not use"), []byte("some other input"))
	if err != nil {
		t.Errorf("failure of prf: %s", err)
	}

	if m1.Equal(m3) {
		t.Errorf("prf ignores input Value")
	}
	m4, _, err := prf([]byte("test key"), []byte("some input"))
	if err != nil {
		t.Errorf("failure of prf: %s", err)
	}
	if m1.Equal(m4) {
		t.Errorf("prf ignores key")
	}
}

func TestColsel(t *testing.T) {
	m1, err := randomMatrixZp(rand.Reader, 17, 17)
	if err != nil {
		t.Fatal(err)
	}
	res := new(matrixZp)
	res.colsel(m1, []int{0, 1, 2})
	if res.rows != m1.rows {
		t.Errorf("wrong number of rows")
	}
	if res.cols != 3 {
		t.Errorf("wrong number of columns")
	}
}

func TestAliasMul(t *testing.T) {
	a, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	b, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	aCopy := newMatrixZp(4, 4)
	aCopy.set(a)
	bCopy := newMatrixZp(4, 4)
	bCopy.set(b)
	a.mul(b, a)
	res := newMatrixZp(0, 0)
	res.mul(bCopy, aCopy)
	if !res.Equal(a) {
		t.Fatalf("failure of mul to be alias safe")
	}
}

func TestAliasAddZp(t *testing.T) {
	a, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	b, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	aCopy := newMatrixZp(4, 4)
	aCopy.set(a)
	bCopy := newMatrixZp(4, 4)
	bCopy.set(b)
	a.add(b, a)
	res := newMatrixZp(0, 0)
	res.add(bCopy, aCopy)
	if !res.Equal(a) {
		t.Fatalf("failure of add to be alias safe")
	}
}

func TestAliasSubZp(t *testing.T) {
	a, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	b, err := randomMatrixZp(rand.Reader, 4, 4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	aCopy := newMatrixZp(4, 4)
	aCopy.set(a)
	bCopy := newMatrixZp(4, 4)
	bCopy.set(b)
	a.sub(b, a)
	res := newMatrixZp(0, 0)
	res.sub(bCopy, aCopy)
	if !res.Equal(a) {
		t.Fatalf("failure of sub to be alias safe")
	}
}

func TestMarshalZp(t *testing.T) {
	a, err := randomMatrixZp(rand.Reader, 7, 9)
	if err != nil {
		t.Fatal(err)
	}
	data, err := a.marshalBinary()
	if err != nil {
		t.Fatalf("failure to serialize: %s", err)
	}
	b := newMatrixZp(0, 0)
	err = b.unmarshalBinary(data)
	if err != nil {
		t.Fatalf("failure to deserialize: %s", err)
	}
	if !a.Equal(b) {
		t.Fatal("failure to roundtrip")
	}

	// test failure to set entry bytes
	scOrder := ff.ScalarOrder()
	scOrder[len(scOrder)-1] += 1
	copy(data[4:pairing.ScalarSize+4], scOrder[:])
	d := newMatrixZp(0, 0)
	err = d.unmarshalBinary(data)
	if err == nil {
		t.Fatal("deserialization of matrixZp with entry larger than scalar order must fail")
	}
}
