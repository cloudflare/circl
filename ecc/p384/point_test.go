//go:build (!noasm && arm64) || (!noasm && amd64)
// +build !noasm,arm64 !noasm,amd64

package p384

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomAffine() *affinePoint {
	params := elliptic.P384().Params()
	k, _ := rand.Int(rand.Reader, params.N)
	return newAffinePoint(params.ScalarBaseMult(k.Bytes()))
}

func randomJacobian() *jacobianPoint {
	params := elliptic.P384().Params()
	P := randomAffine().toJacobian()
	z, _ := rand.Int(rand.Reader, params.P)
	var l fp384
	l.SetBigInt(z)
	fp384Mul(&P.z, &P.z, &l) // z = z * l^1
	fp384Mul(&P.y, &P.y, &l)
	fp384Sqr(&l, &l)
	fp384Mul(&P.x, &P.x, &l) // x = x * l^2
	fp384Mul(&P.y, &P.y, &l) // y = y * l^3
	return P
}

func randomProjective() *projectivePoint {
	return randomJacobian().toProjective()
}

func TestPointDouble(t *testing.T) {
	t.Run("2∞=∞", func(t *testing.T) {
		Z := zeroPoint().toJacobian()
		Z.double()
		got := Z.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("2P=P+P", func(t *testing.T) {
		StdCurve := elliptic.P384()
		for i := 0; i < 128; i++ {
			P := randomJacobian()

			x1, y1 := P.toAffine().toInt()
			wantX, wantY := StdCurve.Double(x1, y1)

			P.double()
			gotX, gotY := P.toAffine().toInt()
			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, P)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})
}

func TestPointAdd(t *testing.T) {
	StdCurve := elliptic.P384()
	Q, R := &jacobianPoint{}, &jacobianPoint{}
	Z := zeroPoint().toJacobian()
	P := randomJacobian()

	t.Run("∞+∞=∞", func(t *testing.T) {
		R.add(Z, Z)
		got := R.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("∞+P=P", func(t *testing.T) {
		R.add(Z, P)
		gotX, gotY := R.toAffine().toInt()
		wantX, wantY := P.toAffine().toInt()
		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, P)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY, P)
		}
	})

	t.Run("P+∞=P", func(t *testing.T) {
		R.add(P, Z)
		gotX, gotY := R.toAffine().toInt()
		wantX, wantY := P.toAffine().toInt()
		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, P)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY, P)
		}
	})

	t.Run("P+(-P)=∞", func(t *testing.T) {
		*Q = *P
		Q.neg()
		R.add(P, Q)
		got := R.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	})

	t.Run("P+P=2P", func(t *testing.T) {
		// This verifies that add function cannot be used for doublings.
		for i := 0; i < 128; i++ {
			P = randomJacobian()

			R.add(P, P)
			gotX, gotY := R.toAffine().toInt()
			wantX, wantY := zeroPoint().toInt()

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, P)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY, P)
			}
		}
	})

	t.Run("P+Q=R", func(t *testing.T) {
		for i := 0; i < 128; i++ {
			P = randomJacobian()
			Q = randomJacobian()

			x1, y1 := P.toAffine().toInt()
			x2, y2 := Q.toAffine().toInt()
			wantX, wantY := StdCurve.Add(x1, y1, x2, y2)

			R.add(P, Q)
			gotX, gotY := R.toAffine().toInt()

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, P, Q)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY, P, Q)
			}
		}
	})
}

func TestPointCompleteAdd(t *testing.T) {
	StdCurve := elliptic.P384()
	Q, R := &projectivePoint{}, &projectivePoint{}
	Z := zeroPoint().toProjective()
	P := randomProjective()

	t.Run("∞+∞=∞", func(t *testing.T) {
		R.completeAdd(Z, Z)
		got := R.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("∞+P=P", func(t *testing.T) {
		R.completeAdd(Z, P)
		gotX, gotY := R.toAffine().toInt()
		wantX, wantY := P.toAffine().toInt()
		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, P)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY, P)
		}
	})

	t.Run("P+∞=P", func(t *testing.T) {
		R.completeAdd(P, Z)
		gotX, gotY := R.toAffine().toInt()
		wantX, wantY := P.toAffine().toInt()
		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, P)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY, P)
		}
	})

	t.Run("P+(-P)=∞", func(t *testing.T) {
		*Q = *P
		Q.cneg(1)
		R.completeAdd(P, Q)
		got := R.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	})

	t.Run("P+P=2P", func(t *testing.T) {
		// This verifies that completeAdd can be used for doublings.
		for i := 0; i < 128; i++ {
			P := randomJacobian()
			PP := P.toProjective()

			R.completeAdd(PP, PP)
			P.double()

			gotX, gotY := R.toAffine().toInt()
			wantX, wantY := P.toAffine().toInt()

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, P)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY, P)
			}
		}
	})

	t.Run("P+Q=R", func(t *testing.T) {
		for i := 0; i < 128; i++ {
			P := randomProjective()
			Q := randomProjective()

			x1, y1 := P.toAffine().toInt()
			x2, y2 := Q.toAffine().toInt()
			wantX, wantY := StdCurve.Add(x1, y1, x2, y2)

			R.completeAdd(P, Q)
			gotX, gotY := R.toAffine().toInt()

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, P, Q)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY, P, Q)
			}
		}
	})
}

func TestPointMixAdd(t *testing.T) {
	StdCurve := elliptic.P384()
	aZ := zeroPoint()
	jZ := zeroPoint().toJacobian()
	R := &jacobianPoint{}
	aQ := &affinePoint{}
	aP := randomAffine()
	jP := randomJacobian()

	t.Run("∞+∞=∞", func(t *testing.T) {
		R.mixadd(jZ, aZ)
		got := R.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("∞+P=P", func(t *testing.T) {
		R.mixadd(jZ, aP)
		gotX, gotY := R.toAffine().toInt()
		wantX, wantY := aP.toInt()
		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, aP)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY)
		}
	})

	t.Run("P+∞=P", func(t *testing.T) {
		R.mixadd(jP, aZ)
		gotX, gotY, gotZ := R.toInt()
		wantX, wantY, wantZ := jP.toInt()
		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, jP)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY)
		}
		if gotZ.Cmp(wantZ) != 0 {
			test.ReportError(t, gotZ, wantZ)
		}
	})

	t.Run("P+(-P)=∞", func(t *testing.T) {
		aQ = jP.toAffine()
		aQ.neg()
		R.mixadd(jP, aQ)
		got := R.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want, jP)
		}
	})

	t.Run("P+P=2P", func(t *testing.T) {
		for i := 0; i < 128; i++ {
			aQ := randomAffine()
			jQ := aQ.toJacobian()

			x, y := aQ.toInt()
			wantX, wantY := StdCurve.Double(x, y)

			R.mixadd(jQ, aQ)
			gotX, gotY := R.toAffine().toInt()

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, aQ)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})

	t.Run("P+Q=R", func(t *testing.T) {
		for i := 0; i < 128; i++ {
			aP = randomAffine()
			jP = randomJacobian()

			x1, y1 := jP.toAffine().toInt()
			x2, y2 := aP.toInt()
			wantX, wantY := StdCurve.Add(x1, y1, x2, y2)

			R.mixadd(jP, aP)
			gotX, gotY := R.toAffine().toInt()

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, jP, aP)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})
}

func TestOddMultiples(t *testing.T) {
	t.Run("invalidOmega", func(t *testing.T) {
		for w := uint(0); w < 2; w++ {
			P := randomAffine()
			PP := P.oddMultiples(w)
			got := len(PP)
			want := 0
			if got != want {
				test.ReportError(t, got, want, w)
			}
		}
	})

	t.Run("validOmega", func(t *testing.T) {
		StdCurve := elliptic.P384()
		var jOdd [4]byte
		for i := 0; i < 32; i++ {
			P := randomAffine()
			X, Y := P.toInt()
			for w := uint(2); w < 10; w++ {
				PP := P.oddMultiples(w)
				for j, jP := range PP {
					binary.BigEndian.PutUint32(jOdd[:], uint32(2*j+1))
					wantX, wantY := StdCurve.ScalarMult(X, Y, jOdd[:])
					gotX, gotY := jP.toAffine().toInt()
					if gotX.Cmp(wantX) != 0 {
						test.ReportError(t, gotX, wantX, w, j)
					}
					if gotY.Cmp(wantY) != 0 {
						test.ReportError(t, gotY, wantY)
					}
				}
			}
		}
	})
}

func BenchmarkPoint(b *testing.B) {
	P := randomJacobian()
	Q := randomJacobian()
	R := randomJacobian()
	QQ := randomProjective()
	RR := randomProjective()
	aR := randomAffine()

	b.Run("addition", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			R.add(P, Q)
		}
	})
	b.Run("fullAddition", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			RR.completeAdd(RR, QQ)
		}
	})
	b.Run("mixadd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.mixadd(P, aR)
		}
	})
	b.Run("double", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.double()
		}
	})
}
