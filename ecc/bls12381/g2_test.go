package bls12381

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/cloudflare/circl/internal/test"
)

func randomG2(t testing.TB) *G2 {
	var P G2
	k := randomScalar(t)
	P.ScalarMult(k, G2Generator())
	if !P.isOnCurve() {
		t.Helper()
		t.Fatal("not on curve")
	}
	return &P
}

func TestG2Add(t *testing.T) {
	const testTimes = 1 << 6
	var Q, R G2
	for i := 0; i < testTimes; i++ {
		P := randomG2(t)
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

func TestG2ScalarMult(t *testing.T) {
	const testTimes = 1 << 6
	var Q G2
	for i := 0; i < testTimes; i++ {
		P := randomG2(t)
		k := randomScalar(t)
		Q.ScalarMult(k, P)
		Q.toAffine()
		got := Q.IsOnG2()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestG2Hash(t *testing.T) {
	const testTimes = 1 << 8

	for _, e := range [...]struct {
		Name string
		Enc  func(p *G2, input, dst []byte)
	}{
		{"Encode", func(p *G2, input, dst []byte) { p.Encode(input, dst) }},
		{"Hash", func(p *G2, input, dst []byte) { p.Hash(input, dst) }},
	} {
		var msg, dst [4]byte
		var p G2
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

func TestG2Serial(t *testing.T) {
	mustOk := "must be ok"
	mustErr := "must be an error"
	t.Run("valid", func(t *testing.T) {
		testTimes := 1 << 6
		var got, want G2
		want.SetIdentity()
		for i := 0; i < testTimes; i++ {
			for _, b := range [][]byte{want.Bytes(), want.BytesCompressed()} {
				err := got.SetBytes(b)
				test.CheckNoErr(t, err, fmt.Sprintf("failure to deserialize: (P:%v b:%x)", want, b))

				if !got.IsEqual(&want) {
					test.ReportError(t, got, want, b)
				}
			}
			want = *randomG2(t)
		}
	})
	t.Run("badLength", func(t *testing.T) {
		q := new(G2)
		p := randomG2(t)
		b := p.Bytes()
		test.CheckIsErr(t, q.SetBytes(b[:0]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:1]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:G2Size-1]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:G2SizeCompressed]), mustErr)
		test.CheckNoErr(t, q.SetBytes(b), mustOk)
		test.CheckNoErr(t, q.SetBytes(append(b, 0)), mustOk)
		b = p.BytesCompressed()
		test.CheckIsErr(t, q.SetBytes(b[:0]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:1]), mustErr)
		test.CheckIsErr(t, q.SetBytes(b[:G2SizeCompressed-1]), mustErr)
		test.CheckNoErr(t, q.SetBytes(b), mustOk)
		test.CheckNoErr(t, q.SetBytes(append(b, 0)), mustOk)
	})
	t.Run("badInfinity", func(t *testing.T) {
		var badInf, p G2
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
		bad := (&[ff.Fp2Size]byte{})[:]
		for i := range bad {
			bad[i] = 0xFF
		}
		var e ff.Fp2
		_ = e[0].Random(rand.Reader)
		_ = e[1].Random(rand.Reader)
		good, err := e.MarshalBinary()
		test.CheckNoErr(t, err, mustOk)

		// bad x, good y
		b := append(bad, good...)
		b[0] = b[0]&0x1F | headerEncoding(0, 0, 0)
		test.CheckIsErr(t, new(G2).SetBytes(b), mustErr)

		// good x, bad y
		b = append(good, bad...)
		b[0] = b[0]&0x1F | headerEncoding(0, 0, 0)
		test.CheckIsErr(t, new(G2).SetBytes(b), mustErr)
	})
	t.Run("noQR", func(t *testing.T) {
		var x ff.Fp2
		// Let x=0, so x^3+4*(u+1) = 4*(u+1), which is not QR because (u+1) is not.
		b, err := x.MarshalBinary()
		test.CheckNoErr(t, err, mustOk)
		b[0] = b[0]&0x1F | headerEncoding(1, 0, 0)
		test.CheckIsErr(t, new(G2).SetBytes(b), mustErr)
	})
	t.Run("notInG2", func(t *testing.T) {
		// p=(0,1) is not on curve.
		var x, y ff.Fp2
		y[0].SetUint64(1)
		bx, err := x.MarshalBinary()
		test.CheckNoErr(t, err, mustOk)
		by, err := y.MarshalBinary()
		test.CheckNoErr(t, err, mustOk)
		b := append(bx, by...)
		b[0] = b[0]&0x1F | headerEncoding(0, 0, 0)
		test.CheckIsErr(t, new(G2).SetBytes(b), mustErr)
	})
}

func BenchmarkG2(b *testing.B) {
	P := randomG2(b)
	Q := randomG2(b)
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

func TestG2Torsion(t *testing.T) {
	if !G2Generator().isRTorsion() {
		t.Fatalf("G2 generator is not r-torsion")
	}
}

func TestG2Bytes(t *testing.T) {
	got := new(G2)
	id := new(G2)
	id.SetIdentity()
	g := G2Generator()
	minusG := G2Generator()
	minusG.Neg()

	type testCase struct {
		header  byte
		length  int
		point   *G2
		toBytes func(G2) []byte
	}

	for i, v := range []testCase{
		{headerEncoding(0, 0, 0), G2Size, randomG2(t), (G2).Bytes},
		{headerEncoding(0, 0, 0), G2Size, g, (G2).Bytes},
		{headerEncoding(1, 0, 0), G2SizeCompressed, g, (G2).BytesCompressed},
		{headerEncoding(1, 0, 1), G2SizeCompressed, minusG, (G2).BytesCompressed},
		{headerEncoding(0, 1, 0), G2Size, id, (G2).Bytes},
		{headerEncoding(1, 1, 0), G2SizeCompressed, id, (G2).BytesCompressed},
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
