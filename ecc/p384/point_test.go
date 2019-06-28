// +build arm64 amd64

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
	x, y := params.ScalarBaseMult(k.Bytes())
	return newAffinePoint(x, y)
}

func randomJacobian() *jacobianPoint {
	params := elliptic.P384().Params()
	P := randomAffine().toJacobian()
	zz, _ := rand.Int(rand.Reader, params.P)
	z := &fp384{}
	z.SetBigInt(zz)
	fp384Mul(&P.x, &P.x, z)
	fp384Mul(&P.y, &P.y, z)
	fp384Mul(&P.z, &P.z, z)
	return P
}

func TestPointDouble(t *testing.T) {
	t.Run("2O=O", func(t *testing.T) {
		Z := &jacobianPoint{}
		Z.double()
		got := Z.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("2P=P+P", func(t *testing.T) {
		params := elliptic.P384().Params()
		for i := 0; i < 128; i++ {
			P := randomJacobian()

			x1, y1 := P.toAffine().toInt()
			wantX, wantY := params.Double(x1, y1)

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
	P, Q := &jacobianPoint{}, &jacobianPoint{}
	R, Z := &jacobianPoint{}, &jacobianPoint{}

	t.Run("O+O=O", func(t *testing.T) {
		R.add(Z, Z)
		got := R.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("O+P=P", func(t *testing.T) {
		R.add(Z, P)
		gotX, gotY, gotZ := R.toInt()
		wantX, wantY, wantZ := P.toInt()
		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, P)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY)
		}
		if gotZ.Cmp(wantZ) != 0 {
			test.ReportError(t, gotZ, wantZ)
		}
	})

	t.Run("P+O=P", func(t *testing.T) {
		R.add(P, Z)
		gotX, gotY, gotZ := R.toInt()
		wantX, wantY, wantZ := P.toInt()
		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, P)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY)
		}
		if gotZ.Cmp(wantZ) != 0 {
			test.ReportError(t, gotZ, wantZ)
		}
	})

	t.Run("P+(-P)=O", func(t *testing.T) {
		*Q = *P
		Q.neg()
		R.add(P, Q)
		got := R.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	})
}

func TestDouble(t *testing.T) {
	// Verify that the `add` function cannot be used for doublings.
	R := &jacobianPoint{}
	for i := 0; i < 128; i++ {
		P := randomJacobian()

		R.add(P, P)
		gotX, gotY, gotZ := R.x, R.y, R.z

		wantX, wantY, wantZ := fp384{}, fp384{}, fp384{}

		if gotX != wantX || gotY != wantY || gotZ != wantZ {
			test.ReportError(t, gotX, wantX, gotY, wantY, gotZ, wantZ, P)
		}
	}
}

func TestAddition(t *testing.T) {
	const testTimes = 1 << 7
	params := elliptic.P384().Params()
	R := &jacobianPoint{}
	for i := 0; i < testTimes; i++ {
		P := randomJacobian()
		Q := randomJacobian()

		x1, y1 := P.toAffine().toInt()
		x2, y2 := Q.toAffine().toInt()
		wantX, wantY := params.Add(x1, y1, x2, y2)

		R.add(P, Q)
		gotX, gotY := R.toAffine().toInt()

		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, P, Q)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY)
		}
	}
}

func TestPointMixAdd(t *testing.T) {
	params := elliptic.P384().Params()
	aZ, aQ := &affinePoint{}, &affinePoint{}
	jZ, R := &jacobianPoint{}, &jacobianPoint{}
	aP := randomAffine()
	jP := randomJacobian()

	t.Run("O+O=O", func(t *testing.T) {
		R.mixadd(jZ, aZ)
		got := R.isZero()
		want := true
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("O+P=P", func(t *testing.T) {
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

	t.Run("P+O=P", func(t *testing.T) {
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

	t.Run("P+(-P)=O", func(t *testing.T) {
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
			wantX, wantY := params.Double(x, y)

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
			wantX, wantY := params.Add(x1, y1, x2, y2)

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
		var jOdd [4]byte
		params := elliptic.P384().Params()
		for i := 0; i < 32; i++ {
			P := randomAffine()
			X, Y := P.toInt()
			for w := uint(2); w < 10; w++ {
				PP := P.oddMultiples(w)
				for j, jP := range PP {
					binary.BigEndian.PutUint32(jOdd[:], uint32(2*j+1))
					wantX, wantY := params.ScalarMult(X, Y, jOdd[:])
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
	aR := randomAffine()

	b.Run("addition", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			R.add(P, Q)
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
