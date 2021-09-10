package bls12381

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/cloudflare/circl/internal/test"
)

func randomScalar(t testing.TB) *Scalar {
	s := &Scalar{}
	err := s.Random(rand.Reader)
	test.CheckNoErr(t, err, "random scalar")
	return s
}

func randomG1(t testing.TB) *G1 {
	P := &G1{}
	u := &ff.Fp{}
	r := &isogG1Point{}

	err := u.Random(rand.Reader)
	test.CheckNoErr(t, err, "random fp")

	r.sswu(u)
	P.evalIsogG1(r)
	P.clearCofactor()
	got := P.IsOnG1()
	want := true

	if got != want {
		test.ReportError(t, got, want, "point not in G1", u)
	}
	return P
}

func TestG1Add(t *testing.T) {
	const testTimes = 1 << 6
	var Q, R G1
	for i := 0; i < testTimes; i++ {
		P := randomG1(t)
		Q = *P
		R = *P
		R.Add(&R, &R)
		R.Neg()
		Q.Double()
		Q.Neg()
		got := R
		want := Q
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestG1ScalarMult(t *testing.T) {
	const testTimes = 1 << 6
	var Q G1
	for i := 0; i < testTimes; i++ {
		P := randomG1(t)
		k := randomScalar(t)
		Q.ScalarMult(k, P)
		Q.toAffine()
		got := Q.IsOnG1()
		want := true
		if got != want {
			test.ReportError(t, got, want, P, k)
		}
	}
}

func TestG1Hash(t *testing.T) {
	const testTimes = 1 << 8

	for _, e := range [...]struct {
		Name string
		Enc  func(p *G1, input, dst []byte)
	}{
		{"Encode", func(p *G1, input, dst []byte) { p.Encode(input, dst) }},
		{"Hash", func(p *G1, input, dst []byte) { p.Hash(input, dst) }},
	} {
		var msg, dst [4]byte
		var p G1
		t.Run(e.Name, func(t *testing.T) {
			for i := 0; i < testTimes; i++ {
				_, _ = rand.Read(msg[:])
				_, _ = rand.Read(dst[:])
				e.Enc(&p, msg[:], dst[:])

				got := p.isRTorsion()
				want := true
				if got != want {
					test.ReportError(t, got, want, e.Name, msg, dst)
				}
			}
		})
	}
}

func BenchmarkG1(b *testing.B) {
	P := randomG1(b)
	Q := randomG1(b)
	k := randomScalar(b)
	var msg, dst [4]byte
	_, _ = rand.Read(msg[:])
	_, _ = rand.Read(dst[:])

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Add(P, Q)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.ScalarMult(k, P)
		}
	})
	b.Run("Hash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Hash(msg[:], dst[:])
		}
	})
}

func TestG1Serial(t *testing.T) {
	mustOk := "must be ok"
	mustErr := "must be an error"
	t.Run("valid", func(t *testing.T) {
		testTimes := 1 << 6
		var got, want G1
		want.SetIdentity()
		for i := 0; i < testTimes; i++ {
			for _, b := range [][]byte{want.Bytes(), want.BytesCompressed()} {
				err := got.SetBytes(b)
				test.CheckNoErr(t, err, fmt.Sprintf("failure to deserialize: (P:%v b:%x)", want, b))

				if !got.IsEqual(&want) {
					test.ReportError(t, got, want, b)
				}
			}
			want = *randomG1(t)
		}
	})
	t.Run("badLength", func(t *testing.T) {
		q := new(G1)
		p := randomG1(t)
		b := p.Bytes()
		test.CheckIsErr(t, q.SetBytes(b[:0]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:1]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:G1Size-1]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:G1SizeCompressed]), mustErr)
		test.CheckNoErr(t, q.SetBytes(b), mustOk)
		test.CheckNoErr(t, q.SetBytes(append(b, 0)), mustOk)
		b = p.BytesCompressed()
		test.CheckIsErr(t, q.SetBytes(b[:0]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:1]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:G1SizeCompressed-1]), mustErr)
		test.CheckNoErr(t, q.SetBytes(b), mustOk)
		test.CheckNoErr(t, q.SetBytes(append(b, 0)), mustOk)
	})
	t.Run("badInfinity", func(t *testing.T) {
		var badInf, p G1
		badInf.SetIdentity()
		b := badInf.Bytes()
		b[0] |= 0x1F
		err := p.SetBytes(b)
		test.CheckIsErr(t, err, mustErr)
		b[0] &= 0xE0
		b[1] = 0xFF
		err = p.SetBytes(b)
		test.CheckIsErr(t, err, mustErr)
	})
	t.Run("badCoords", func(t *testing.T) {
		bad := (&[ff.FpSize]byte{})[:]
		for i := range bad {
			bad[i] = 0xFF
		}
		var e ff.Fp
		_ = e.Random(rand.Reader)
		good, err := e.MarshalBinary()
		test.CheckNoErr(t, err, mustOk)

		// bad x, good y
		b := append(bad, good...)
		b[0] = b[0]&0x1F | headerEncoding(0, 0, 0)
		test.CheckIsErr(t, new(G1).SetBytes(b), mustErr)

		// good x, bad y
		b = append(good, bad...)
		b[0] = b[0]&0x1F | headerEncoding(0, 0, 0)
		test.CheckIsErr(t, new(G1).SetBytes(b), mustErr)
	})
	t.Run("noQR", func(t *testing.T) {
		var x ff.Fp
		x.SetUint64(1) // Let x=1, so x^3+4 = 5, which is not QR.
		b, err := x.MarshalBinary()
		test.CheckNoErr(t, err, mustOk)
		b[0] = b[0]&0x1F | headerEncoding(1, 0, 0)
		test.CheckIsErr(t, new(G1).SetBytes(b), mustErr)
	})
	t.Run("notInG1", func(t *testing.T) {
		// p=(0,1) is not on curve.
		var x, y ff.Fp
		y.SetUint64(1)
		bx, err := x.MarshalBinary()
		test.CheckNoErr(t, err, mustOk)
		by, err := y.MarshalBinary()
		test.CheckNoErr(t, err, mustOk)
		b := append(bx, by...)
		b[0] = b[0]&0x1F | headerEncoding(0, 0, 0)
		test.CheckIsErr(t, new(G1).SetBytes(b), mustErr)
	})
}

func TestG1Affinize(t *testing.T) {
	N := 20
	testTimes := 1 << 6
	g1 := make([]*G1, N)
	g2 := make([]*G1, N)
	for i := 0; i < testTimes; i++ {
		for j := 0; j < N; j++ {
			g1[j] = randomG1(t)
			g2[j] = &G1{}
			*g2[j] = *g1[j]
		}
		affinize(g2)
		for j := 0; j < N; j++ {
			g1[j].toAffine()
			if !g1[j].IsEqual(g2[j]) {
				t.Fatal("failure to preserve points")
			}
			if g2[j].z.IsEqual(&g1[j].z) != 1 {
				t.Fatal("failure to make affine")
			}
		}
	}
}

func TestG1Torsion(t *testing.T) {
	if !G1Generator().isRTorsion() {
		t.Fatalf("G1 generator is not r-torsion")
	}
}

func TestG1Bytes(t *testing.T) {
	got := new(G1)
	id := new(G1)
	id.SetIdentity()
	g := G1Generator()
	minusG := G1Generator()
	minusG.Neg()

	type testCase struct {
		header  byte
		length  int
		point   *G1
		toBytes func(G1) []byte
	}

	for i, v := range []testCase{
		{headerEncoding(0, 0, 0), G1Size, randomG1(t), (G1).Bytes},
		{headerEncoding(0, 0, 0), G1Size, g, (G1).Bytes},
		{headerEncoding(1, 0, 0), G1SizeCompressed, g, (G1).BytesCompressed},
		{headerEncoding(1, 0, 1), G1SizeCompressed, minusG, (G1).BytesCompressed},
		{headerEncoding(0, 1, 0), G1Size, id, (G1).Bytes},
		{headerEncoding(1, 1, 0), G1SizeCompressed, id, (G1).BytesCompressed},
	} {
		b := v.toBytes(*v.point)
		test.CheckOk(len(b) == v.length, fmt.Sprintf("bad encoding size (case:%v point:%v b:%x)", i, v.point, b), t)
		test.CheckOk(b[0]&0xE0 == v.header, fmt.Sprintf("bad encoding header (case:%v point:%v b:%x)", i, v.point, b), t)

		err := got.SetBytes(b)
		want := v.point
		if err != nil || !got.IsEqual(want) {
			test.ReportError(t, got, want, i, b)
		}
	}
}
